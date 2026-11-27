package session

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/transport"
)

const (
	testName   = "tunnel-us-east.seawise.dev"
	testEdge   = "edge-us-east-0"
	testServer = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
)

func seedKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("session test key: " + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func deviceKeyID() string { return protocol.KeyID(pubOf(seedKey("device"))) }

func testKeySet(t testing.TB) *protocol.KeySet {
	t.Helper()
	root := seedKey("root")
	entry := func(name, role string, named bool) protocol.KeySetEntry {
		pub := pubOf(seedKey(name))
		e := protocol.KeySetEntry{KID: protocol.KeyID(pub), Role: role, X: protocol.PublicJWK(pub).X, Status: protocol.StatusActive}
		if named {
			e.Name = name
		}
		return e
	}
	tok, err := protocol.NewKeySet(root, 1, time.Now().Unix(), []protocol.KeySetEntry{
		entry("control", protocol.RoleControl, false), entry(testEdge, protocol.RoleEdge, true),
	})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{pubOf(root)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func sign(t testing.TB, key, typ string, c any) string {
	t.Helper()
	tok, err := protocol.NewKeyed(seedKey(key), typ, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var testSessionID = []byte("0123456789abcdef")

func routeSetMsg(t testing.TB, version int64, sessionID []byte) *pb.ControlMessage {
	c := map[string]any{"edge": testEdge, "server_id": testServer, "session_id": base64.RawURLEncoding.EncodeToString(sessionID),
		"version": version, "iat": 1700000000, "routes": []map[string]any{{"app_id": "11111111-2222-4333-8444-555555555555",
			"fqdn": "app.example.seawise.dev", "public": false, "access_version": 1}}}
	return &pb.ControlMessage{Body: &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: sign(t, testEdge, protocol.TypRouteSet, c)}}}
}

func flagsDoc(t testing.TB, gen int64, global string) string {
	salt := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	return sign(t, "control", protocol.TypFlags, map[string]any{"generation": gen, "global": global, "rollout_permille": 0,
		"salt": salt, "allow": []string{}, "deny": []string{}, "iat": 1700000000})
}

func stateTok(t testing.TB, nonce, device, account string, at int64) string {
	return sign(t, "control", protocol.TypState, map[string]any{"server_id": testServer, "key_id": deviceKeyID(),
		"time": at, "nonce": nonce, "device_status": device, "account_status": account})
}

// fakeClock fires After channels when Advance passes them.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Unix(1700000000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, waiter{c.now.Add(d), ch})
	return ch
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	keep := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.at.After(c.now) {
			w.ch <- c.now
		} else {
			keep = append(keep, w)
		}
	}
	c.waiters = keep
	c.mu.Unlock()
}

// fakeConn is a session the test plays the edge of.
type fakeConn struct {
	info   ConnInfo
	in     chan *pb.ControlMessage
	sent   chan *pb.ControlMessage
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	rx     time.Time
	alive  func() time.Time // until setRx: bytes keep arriving
}

func newConn(c transport.Carriage, clock *fakeClock) *fakeConn {
	return &fakeConn{info: ConnInfo{Carriage: c, EdgeID: testEdge, SessionID: testSessionID, TimeNonce: make([]byte, 16),
		PingInterval: 20 * time.Second, PingTimeout: 15 * time.Second},
		in: make(chan *pb.ControlMessage, 16), sent: make(chan *pb.ControlMessage, 64), closed: make(chan struct{}), alive: clock.Now}
}

func (c *fakeConn) Send(m *pb.ControlMessage) error {
	select {
	case <-c.closed:
		return io.ErrClosedPipe
	default:
	}
	c.sent <- m
	return nil
}

func (c *fakeConn) Next() (*pb.ControlMessage, error) {
	select {
	case m := <-c.in:
		return m, nil
	case <-c.closed:
		return nil, io.EOF
	}
}

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *fakeConn) LastReceived() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.alive != nil {
		return c.alive()
	}
	return c.rx
}

func (c *fakeConn) setRx(t time.Time) {
	c.mu.Lock()
	c.rx, c.alive = t, nil
	c.mu.Unlock()
}

func (c *fakeConn) Info() ConnInfo { return c.info }

// expect waits for a sent message matching f.
func (c *fakeConn) expect(t testing.TB, what string, f func(*pb.ControlMessage) bool) *pb.ControlMessage {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-c.sent:
			if f(m) {
				return m
			}
		case <-deadline:
			t.Fatalf("no %s sent", what)
			return nil
		}
	}
}

type dialReq struct {
	carriage transport.Carriage
	reply    chan dialRes
}

type dialRes struct {
	conn Conn
	err  error
}

type harness struct {
	t      *testing.T
	m      *Manager
	clock  *fakeClock
	dials  chan dialReq
	net    chan struct{}
	routes chan *claims.RouteSet
	hb     *hbServer
	cancel context.CancelFunc
	done   chan error
	ks     *protocol.KeySet
	dir    string
}

type hbServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	answer    func(nonce string) (int, string)
	nonces    chan string
	headers   []http.Header
	connected []bool
	bodies    [][]byte
	keyed     func(nonce, kid string) (int, string)
}

func newHBServer(t testing.TB) *hbServer {
	h := &hbServer{nonces: make(chan string, 16)}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Nonce     string `json:"nonce"`
			Connected bool   `json:"frp_connected"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		h.mu.Lock()
		h.headers = append(h.headers, r.Header.Clone())
		h.connected = append(h.connected, body.Connected)
		h.bodies = append(h.bodies, b)
		f, keyed := h.answer, h.keyed
		h.mu.Unlock()
		if keyed != nil {
			kid := ""
			if res, err := protocol.VerifyDPoP(r.Header.Get("DPoP"), protocol.DPoPRequest{Method: http.MethodPost, URL: h.srv.URL + HeartbeatPath, Body: b},
				func(string) bool { return true }, func(string, string) bool { return true }); err == nil {
				kid = res.KeyID
			}
			f = func(n string) (int, string) { return keyed(n, kid) }
		}
		select {
		case h.nonces <- body.Nonce:
		default:
		}
		code, out := http.StatusServiceUnavailable, ""
		if f != nil {
			code, out = f(body.Nonce)
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hbServer) set(f func(nonce string) (int, string)) {
	h.mu.Lock()
	h.answer = f
	h.mu.Unlock()
}

// setKeyed answers by the key that proved the request.
func (h *hbServer) setKeyed(f func(nonce, kid string) (int, string)) {
	h.mu.Lock()
	h.keyed = f
	h.mu.Unlock()
}

func answerJSON(state, flags string) string {
	f := "null"
	if flags != "" {
		f = `"` + flags + `"`
	}
	return `{"data":{"status":"state","signed_time":"` + state + `","flags":` + f + `}}`
}

type option func(*Config)

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	h := &harness{t: t, clock: newClock(), dials: make(chan dialReq, 8), net: make(chan struct{}, 1),
		routes: make(chan *claims.RouteSet, 16), hb: newHBServer(t), done: make(chan error, 1), ks: testKeySet(t), dir: t.TempDir()}
	cfg := Config{
		Dial: func(ctx context.Context, name string, c transport.Carriage) (Conn, error) {
			if name != testName {
				return nil, errors.New("wrong name")
			}
			r := dialReq{carriage: c, reply: make(chan dialRes, 1)}
			h.dials <- r
			select {
			case res := <-r.reply:
				return res.conn, res.err
			case <-ctx.Done():
				return nil, &transport.Error{Kind: transport.Local, Reason: "canceled", Err: ctx.Err()}
			}
		},
		Name: testName, ServerID: testServer, KeyID: deviceKeyID,
		KeySet:    func() *protocol.KeySet { return h.ks },
		Heartbeat: &Heartbeat{Origin: h.hb.srv.URL, Key: func() crypto.Signer { return seedKey("device") }, Client: h.hb.srv.Client(), Version: "2.0.0"},
		DataDir:   h.dir, Network: h.net, Clock: h.clock,
		Rand:     func(n int64) int64 { return n - 1 },
		OnRoutes: func(rs *claims.RouteSet) { h.routes <- rs },
		Logger:   slog.New(slog.DiscardHandler),
	}
	for _, o := range opts {
		o(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.m = m
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("manager did not stop")
		}
	})
	return h
}

func (h *harness) dial() dialReq {
	h.t.Helper()
	select {
	case r := <-h.dials:
		return r
	case <-time.After(5 * time.Second):
		h.t.Fatal("no dial")
		return dialReq{}
	}
}

func (h *harness) noDial(d time.Duration) {
	h.t.Helper()
	select {
	case r := <-h.dials:
		h.t.Fatalf("unexpected dial over %s", r.carriage)
	case <-time.After(d):
	}
}

// up answers a dial with a session and delivers its first RouteSet.
func (h *harness) up(r dialReq) *fakeConn {
	h.t.Helper()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	c.in <- routeSetMsg(h.t, 1, testSessionID)
	c.expect(h.t, "RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 1 })
	h.wait("session up", func(s Status) bool { return s.Up })
	return c
}

func (h *harness) fail(r dialReq, cause string) {
	r.reply <- dialRes{err: &transport.Error{Kind: transport.Blocked, Cause: cause}}
	h.settle()
}

func (h *harness) refuse(r dialReq, code pb.RefuseCode) {
	kind := transport.Refused
	switch code {
	case pb.RefuseCode_EDGE_NOT_READY, pb.RefuseCode_OVERLOADED, pb.RefuseCode_BAD_REQUEST:
		kind = transport.Transient
	case pb.RefuseCode_INVALID_PROOF, pb.RefuseCode_KEY_REVOKED, pb.RefuseCode_NOT_ENROLLED, pb.RefuseCode_ACCOUNT_SUSPENDED:
		kind = transport.Auth
	}
	r.reply <- dialRes{err: &transport.Error{Kind: kind, Code: code}}
	h.settle()
}

// settle lets the loop take in what the test just sent.
func (h *harness) settle() { time.Sleep(20 * time.Millisecond) }

func (h *harness) wait(what string, f func(Status) bool) Status {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := h.m.Status()
		if f(s) {
			return s
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s: status %+v", what, s)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// advance moves the clock in steps of at least 1 s, at most 100 steps
// for long spans, so the loop sees the deadlines in order.
func (h *harness) advance(d time.Duration) {
	step := max(time.Second, d/100)
	for d > 0 {
		s := min(step, d)
		h.clock.Advance(s)
		d -= s
		time.Sleep(time.Millisecond)
	}
}

func jsonDecode(b []byte, v any) error { return json.Unmarshal(b, v) }
