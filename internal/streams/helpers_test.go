package streams

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/seawise-io/seawise-client/tunnelwire/caps"
	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
	"google.golang.org/protobuf/proto"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
	"github.com/seawise/client/internal/visitor"
)

const (
	appA  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000a1"
	appB  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000b2"
	sidA  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000c3"
	userA = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000d5"
	acctA = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000e6"
	exp0  = int64(1_800_000_000)
	edge0 = "edge-us-east-0"
)

var b64 = base64.RawURLEncoding

func testKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("streams-test/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func compact(k ed25519.PrivateKey, typ string, c any) string {
	pub := k.Public().(ed25519.PublicKey)
	h, _ := json.Marshal(map[string]string{"typ": typ, "alg": "EdDSA", "kid": protocol.KeyID(pub)})
	p, _ := json.Marshal(c)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	return in + "." + b64.EncodeToString(ed25519.Sign(k, []byte(in)))
}

func token(aud string, exp int64) string {
	return compact(testKey("visitor"), visitor.TypVisitor, map[string]any{"sid": sidA, "sub": userA, "epoch": 0, "aud": aud,
		"acct": acctA, "gen": 1, "av": 3, "iat": exp - 900, "exp": exp})
}

func staleOk(k ed25519.PrivateKey, aud string, exp int64) string {
	return compact(k, visitor.TypStaleOk, map[string]any{"edge": edge0, "aud": aud, "sid": sidA, "until": exp + 1800, "iat": exp})
}

func testKeySet(t testing.TB) *protocol.KeySet {
	t.Helper()
	root := testKey("root")
	entry := func(k ed25519.PrivateKey, role, name string) protocol.KeySetEntry {
		pub := k.Public().(ed25519.PublicKey)
		return protocol.KeySetEntry{KID: protocol.KeyID(pub), Role: role, X: b64.EncodeToString(pub), Status: protocol.StatusActive, Name: name}
	}
	tok, err := protocol.NewKeySet(root, 1, 1_700_000_000, []protocol.KeySetEntry{
		entry(testKey("visitor"), protocol.RoleVisitor, ""), entry(testKey("edge"), protocol.RoleEdge, edge0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// syncBuf is a log sink safe for concurrent writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// env is one agent data-stream server with a forwarder and a fake clock,
// and the edge end of one or more sessions.
type env struct {
	t       *testing.T
	srv     *Server
	fwd     *forwarder.Forwarder
	gate    *visitor.Gate
	ks      *protocol.KeySet
	mode    atomic.Value // visitor.Mode
	now     atomic.Int64
	targets atomic.Pointer[[]store.Target]
	mu      sync.Mutex
	entries []accesslog.Entry
	logs    *syncBuf
	cfg     Config
}

type edgeSide struct {
	t      *testing.T
	mux    *yamux.Session
	agent  *yamux.Session
	routes atomic.Pointer[claims.RouteSet]
	ended  *session.AppEnds
	done   chan struct{}
	cancel context.CancelFunc
}

func newEnv(t *testing.T, tweak func(*Config, *forwarder.Config)) *env {
	t.Helper()
	e := &env{t: t, ks: testKeySet(t), logs: &syncBuf{}}
	e.mode.Store(visitor.Observe)
	e.now.Store(exp0 - 60)
	e.targets.Store(&[]store.Target{})
	var err error
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	e.gate, err = visitor.New(visitor.Config{
		KeySet: func() *protocol.KeySet { return e.ks },
		Mode:   func() visitor.Mode { return e.mode.Load().(visitor.Mode) },
		Now:    func() time.Time { return time.Unix(e.now.Load(), 0) },
		Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	fcfg := forwarder.Config{Logger: log, DialTimeout: time.Second,
		Resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no DNS in tests") }}
	e.cfg = Config{Gate: e.gate, Targets: func() []store.Target { return *e.targets.Load() },
		Record: func(en accesslog.Entry) {
			e.mu.Lock()
			e.entries = append(e.entries, en)
			e.mu.Unlock()
		}, Logger: log}
	if tweak != nil {
		tweak(&e.cfg, &fcfg)
	}
	e.fwd = forwarder.New(fcfg)
	t.Cleanup(e.fwd.Close)
	if e.cfg.Dial == nil {
		e.cfg.Dial = e.fwd.Dial
	}
	e.srv, err = New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// app stores a target for the server app id and admits it.
func (e *env) app(server, local string, port int, serverPublic bool) {
	e.t.Helper()
	ts := append([]store.Target(nil), *e.targets.Load()...)
	ts = append(ts, store.Target{LocalID: local, ServerServiceID: server, Name: local, Host: "127.0.0.1", Port: port,
		Subdomain: local, Source: store.SourceLocal, ServerPublic: serverPublic})
	e.targets.Store(&ts)
	e.sync()
}

func (e *env) sync() {
	var apps []forwarder.App
	for _, t := range *e.targets.Load() {
		apps = append(apps, forwarder.App{ID: t.LocalID, Host: t.Host, Port: t.Port, Rule: targetpolicy.RuleFor(t)})
	}
	e.fwd.Sync(apps)
}

func (e *env) logged() []accesslog.Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]accesslog.Entry(nil), e.entries...)
}

// waitLogged waits for n entries.
func (e *env) waitLogged(n int) []accesslog.Entry {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if l := e.logged(); len(l) >= n {
			return l
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("want %d log entries, have %v", n, e.logged())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func routeSet(apps map[string]bool) *claims.RouteSet {
	rs := &claims.RouteSet{Edge: edge0, Version: 1}
	for id, public := range apps {
		rs.Routes = append(rs.Routes, claims.Route{AppID: id, FQDN: id[len(id)-2:] + ".example.seawise.dev", Public: public, AccessVersion: 1})
	}
	return rs
}

// session starts a session: an agent yamux client and an edge server end
// over loopback TCP, served by e.srv.
func (e *env) session(rs *claims.RouteSet, maxStreams int, capabilities ...string) *edgeSide {
	e.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	ac, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		e.t.Fatal(err)
	}
	ec := <-accepted
	cfg, err := caps.YamuxConfig(caps.DefaultAgentMaxStreams)
	if err != nil {
		e.t.Fatal(err)
	}
	agent, err := yamux.Client(ac, cfg, caps.NewAgentGate(caps.AgentBudget, caps.DefaultAgentMaxStreams).NewSpan)
	if err != nil {
		e.t.Fatal(err)
	}
	mux, err := yamux.Server(ec, cfg, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	s := &edgeSide{t: e.t, mux: mux, agent: agent, done: make(chan struct{}), ended: session.NewAppEnds()}
	s.routes.Store(rs)
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() {
		defer close(s.done)
		e.srv.Serve(ctx, session.DataSession{Mux: agent, Capabilities: capabilities, MaxStreams: maxStreams, EdgeID: edge0, Routes: s.routes.Load, Ended: s.ended})
	}()
	e.t.Cleanup(func() {
		cancel()
		_ = mux.Close()
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			e.t.Error("Serve did not return")
		}
	})
	return s
}

func appBytes(id string) []byte {
	b, _ := hexUUID(id)
	return b
}

func hexUUID(id string) ([]byte, error) {
	var out []byte
	h := strings.ReplaceAll(id, "-", "")
	for i := 0; i+1 < len(h); i += 2 {
		var v byte
		for _, c := range h[i : i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			default:
				return nil, errors.New("hex")
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func header(app, tok string) *pb.StreamHeader {
	return &pb.StreamHeader{Version: wire.HeaderVersion, Type: pb.StreamType_HTTP, AppId: appBytes(app), VisitorToken: tok,
		ClientIp: []byte{203, 0, 113, 9}, Scheme: pb.Scheme_HTTPS, Alpn: "http/1.1", EdgeTimeMs: 1, TraceId: bytes.Repeat([]byte{7}, 16)}
}

// open opens a data stream, writes the header and the request bytes at
// once (as the edge does) and returns the stream.
func (s *edgeSide) open(h *pb.StreamHeader, req string) *yamux.Stream {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.mux.OpenStream(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	f, err := wire.AppendStreamHeader(nil, h, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := st.Write(append(f, req...)); err != nil {
		s.t.Fatal(err)
	}
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	return st
}

func readReply(t *testing.T, st *yamux.Stream) pb.ReplyCode {
	t.Helper()
	code, err := wire.ReadStreamReply(st)
	if err != nil {
		t.Fatal("reply:", err)
	}
	return code
}

// exchange opens a stream and returns the reply and everything after it
// up to the agent's FIN, then closes the stream as the edge does. A reset
// may overtake the reply.
func (s *edgeSide) exchange(h *pb.StreamHeader, req string) (pb.ReplyCode, string, error) {
	s.t.Helper()
	st := s.open(h, req)
	defer st.Close()
	code, err := wire.ReadStreamReply(st)
	if err != nil {
		return 0, "", err
	}
	b, err := io.ReadAll(st)
	return code, string(b), err
}

func get(path string, extra ...string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: app.example.seawise.dev\r\nConnection: close\r\n" + strings.Join(extra, "") + "\r\n"
}

// rawTarget is an app that records each request's bytes up to the end of
// the head (and the body when a Content-Length or chunked framing says so)
// and answers with resp.
type rawTarget struct {
	port   int
	mu     sync.Mutex
	heads  []string
	accept atomic.Int32
	serve  func(c net.Conn, br *bufio.Reader, head string)
}

func newTarget(t *testing.T, serve func(c net.Conn, br *bufio.Reader, head string)) *rawTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	rt := &rawTarget{port: ln.Addr().(*net.TCPAddr).Port, serve: serve}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rt.accept.Add(1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				var head strings.Builder
				for {
					line, err := br.ReadString('\n')
					head.WriteString(line)
					if err != nil || line == "\r\n" {
						break
					}
				}
				if head.Len() > 0 {
					rt.mu.Lock()
					rt.heads = append(rt.heads, head.String())
					rt.mu.Unlock()
				}
				rt.serve(c, br, head.String())
			}()
		}
	}()
	return rt
}

func (rt *rawTarget) got() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]string(nil), rt.heads...)
}

func okTarget(t *testing.T) *rawTarget {
	return newTarget(t, func(c net.Conn, _ *bufio.Reader, _ string) {
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
}

const okResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

// goroutines waits until the goroutine count is back to at most n.
func goroutines(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines %d > %d\n%s", runtime.NumGoroutine(), n, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func numGoroutine() int { return runtime.NumGoroutine() }

func tgGoroutines(*rawTarget) int { return 3 }

func marshalRaw(h *pb.StreamHeader) ([]byte, error) { return proto.Marshal(h) }
