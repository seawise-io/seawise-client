package devapi

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
)

var deviceKey = func() ed25519.PrivateKey {
	s := sha256.Sum256([]byte("devapi test device"))
	return ed25519.NewKeyFromSeed(s[:])
}()

// request is one call as the fake device API saw it.
type request struct {
	relayed            bool
	method, path, key  string
	nonce, jti         string
	body               []byte
	userAgent, ctype   string
	idempotencyPresent bool
}

type stored struct {
	hash   [32]byte
	status int
	body   []byte
}

// fakeAPI is the device API behind both transports: proof checked against
// the twin's method and URL, nonce flow, and per-key dedupe of writes
// (stored answer replayed, another body refused), as device-api does.
type fakeAPI struct {
	t      testing.TB
	srv    *httptest.Server
	mu     sync.Mutex
	nonce  string
	nonces int
	seen   []request
	store  map[string]stored
	runs   map[string]int
	// answer is the twin's answer to an executed call (default 200 "{}").
	answer func(r request) (int, []byte, string)
	// challenge asks for a new nonce on every call.
	challenge bool
}

func (a *fakeAPI) setNonce(n string) {
	a.mu.Lock()
	a.nonce = n
	a.mu.Unlock()
}

func newAPI(t testing.TB) *fakeAPI {
	a := &fakeAPI{t: t, store: map[string]stored{}, runs: map[string]int{}}
	a.nextNonce()
	a.srv = httptest.NewTLSServer(http.HandlerFunc(a.serveHTTP))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *fakeAPI) nextNonce() string {
	a.nonces++
	a.nonce = "n1.AAAAA" + strconv.Itoa(a.nonces%10) + ".c2VydmVyLW5vbmNl"
	return a.nonce
}

func (a *fakeAPI) origin() string { return a.srv.URL }

type twinAnswer struct {
	status     int
	body       []byte
	nonce      string
	retryAfter string
}

func (a *fakeAPI) handle(r request, proof string) twinAnswer {
	a.mu.Lock()
	defer a.mu.Unlock()
	res, err := protocol.VerifyDPoP(proof, protocol.DPoPRequest{Method: r.method, URL: a.origin() + r.path, Body: r.body},
		func(string) bool { return true }, func(string, string) bool { return true })
	if err != nil || res.KeyID != protocol.KeyID(deviceKey.Public().(ed25519.PublicKey)) {
		return twinAnswer{status: 401, body: []byte(`{"error":"invalid_proof","code":"invalid_proof"}`)}
	}
	r.nonce, r.jti = res.Claims.Nonce, res.Claims.JTI
	a.seen = append(a.seen, r)
	if r.nonce != a.nonce || a.challenge {
		return twinAnswer{status: 401, body: []byte(`{"error":"use_dpop_nonce","code":"use_dpop_nonce"}`), nonce: a.nextNonce()}
	}
	write := r.method == http.MethodPost && r.path != "/device/v2/health" && r.path != "/device/v2/heartbeat"
	scope := r.method + " " + r.path + " " + r.key
	h := sha256.Sum256(r.body)
	if write && r.key != "" {
		if s, ok := a.store[scope]; ok {
			if s.hash != h {
				return twinAnswer{status: 409, body: []byte(`{"error":"idempotency_mismatch"}`)}
			}
			return twinAnswer{status: s.status, body: s.body}
		}
	}
	a.runs[scope]++
	status, body, retry := 200, []byte("{}"), ""
	if a.answer != nil {
		status, body, retry = a.answer(r)
	}
	if write && r.key != "" && status < 500 {
		a.store[scope] = stored{hash: h, status: status, body: body}
	}
	return twinAnswer{status: status, body: body, retryAfter: retry}
}

func (a *fakeAPI) serveHTTP(w http.ResponseWriter, hr *http.Request) {
	b, _ := io.ReadAll(hr.Body)
	_, present := hr.Header["Idempotency-Key"]
	r := request{method: hr.Method, path: hr.URL.Path, key: hr.Header.Get("Idempotency-Key"), body: b,
		userAgent: hr.Header.Get("User-Agent"), ctype: hr.Header.Get("Content-Type"), idempotencyPresent: present}
	ans := a.handle(r, hr.Header.Get("DPoP"))
	if ans.nonce != "" {
		w.Header().Set("DPoP-Nonce", ans.nonce)
	}
	if ans.status == 401 && ans.nonce != "" {
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
	}
	if ans.retryAfter != "" {
		w.Header().Set("Retry-After", ans.retryAfter)
	}
	w.WriteHeader(ans.status)
	_, _ = w.Write(ans.body)
}

func (a *fakeAPI) requests() []request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]request(nil), a.seen...)
}

func (a *fakeAPI) executed(scope string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.runs[scope]
}

// fakeEdge carries stream 0 calls to the fake API as the edge relays them
// (5B-08): device-api's answer unchanged as DONE, anything else
// UNAVAILABLE. fault scripts what happens to the next calls.
type fakeEdge struct {
	api   *fakeAPI
	mu    sync.Mutex
	calls []*pb.DeviceCall
	down  bool
	fault []func(call *pb.DeviceCall) (*pb.DeviceResult, bool, error)
}

var errNoSession = errors.New("no tunnel session up")

func (e *fakeEdge) Relay(ctx context.Context, call *pb.DeviceCall) (*pb.DeviceResult, error) {
	e.mu.Lock()
	if e.down {
		e.mu.Unlock()
		return nil, errNoSession
	}
	call.CallId = uint32(len(e.calls) + 1)
	e.calls = append(e.calls, call)
	var f func(*pb.DeviceCall) (*pb.DeviceResult, bool, error)
	if len(e.fault) > 0 {
		f, e.fault = e.fault[0], e.fault[1:]
	}
	e.mu.Unlock()
	if _, err := wire.EncodeControl(&pb.ControlMessage{Schema: wire.SchemaVersion, Seq: 1, Body: &pb.ControlMessage_DeviceCall{DeviceCall: call}}, wire.FromAgent); err != nil {
		e.api.t.Errorf("invalid DeviceCall: %v", err)
		return nil, err
	}
	if f != nil {
		if r, done, err := f(call); done {
			return r, err
		}
	}
	return e.relay(call), nil
}

func (e *fakeEdge) relay(call *pb.DeviceCall) *pb.DeviceResult {
	method, path, err := wire.TwinPath(call.GetMethod(), call.GetPathSuffix())
	if err != nil {
		return &pb.DeviceResult{CallId: call.CallId, Class: pb.ResultClass_UNAVAILABLE, RetryAfterMs: 1000}
	}
	ans := e.api.handle(request{relayed: true, method: method, path: path, key: hex.EncodeToString(call.GetIdempotencyKey()), body: call.GetBody()}, call.GetDpop())
	var ms uint32
	if s, err := strconv.Atoi(ans.retryAfter); err == nil {
		ms = uint32(min(s*1000, 300000))
	}
	return &pb.DeviceResult{CallId: call.CallId, Class: pb.ResultClass_DONE, HttpStatus: uint32(ans.status), Body: ans.body, DpopNonce: ans.nonce, RetryAfterMs: ms}
}

func (e *fakeEdge) sent() []*pb.DeviceCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*pb.DeviceCall(nil), e.calls...)
}

func (e *fakeEdge) push(f ...func(*pb.DeviceCall) (*pb.DeviceResult, bool, error)) {
	e.mu.Lock()
	e.fault = append(e.fault, f...)
	e.mu.Unlock()
}

func (e *fakeEdge) setDown(d bool) {
	e.mu.Lock()
	e.down = d
	e.mu.Unlock()
}

type env struct {
	api    *fakeAPI
	edge   *fakeEdge
	caller *devicecall.Caller
	c      *Client
}

func newEnv(t testing.TB, opts ...func(*Config)) *env {
	t.Helper()
	api := newAPI(t)
	caller, err := devicecall.New(devicecall.Config{Client: api.srv.Client(), Version: "2.0.0", Now: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{api: api, edge: &fakeEdge{api: api}, caller: caller}
	cfg := Config{Caller: caller, Origin: api.origin, Key: func() crypto.Signer { return deviceKey }, Stream0: e.edge}
	for _, o := range opts {
		o(&cfg)
	}
	e.c, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

const key1 = "0123456789abcdef0123456789abcdef"

func registerCall() Call {
	return Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: key1, Body: []byte(`{"apps":[{"local_id":"a"}]}`)}
}

func (a *fakeAPI) current() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nonce
}
