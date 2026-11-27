package appsync

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
	"sync"
	"testing"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/devapi"
	"github.com/seawise/client/internal/devicecall"
)

// carriers are stream 0 (an edge relaying to the fake API) and HTTPS (a
// TLS server in front of the same fake API).
type carriers struct {
	api       *fakeAPI
	mu        sync.Mutex
	edgeDown  bool
	httpsDown bool
	// dropAfter ends the session after the device API ran a call of this
	// method, once.
	dropAfter pb.DeviceMethod
	relayed   []*pb.DeviceCall
	httpsKeys []string
}

func (c *carriers) Relay(ctx context.Context, call *pb.DeviceCall) (*pb.DeviceResult, error) {
	c.mu.Lock()
	if c.edgeDown {
		c.mu.Unlock()
		return nil, errors.New("no tunnel session up")
	}
	c.relayed = append(c.relayed, call)
	drop := c.dropAfter == call.GetMethod()
	if drop {
		c.dropAfter = pb.DeviceMethod_METHOD_UNSPECIFIED
	}
	c.mu.Unlock()
	key := ""
	if call.GetMethod() == pb.DeviceMethod_REGISTER_APPS || call.GetMethod() == pb.DeviceMethod_DELETE_APPS {
		key = hex.EncodeToString(call.GetIdempotencyKey())
	}
	r, err := c.api.Do(ctx, Request{Method: call.GetMethod(), Key: key, Body: call.GetBody()})
	if err != nil {
		return &pb.DeviceResult{CallId: call.CallId, Class: pb.ResultClass_UNAVAILABLE, RetryAfterMs: 1000}, nil
	}
	if drop {
		return nil, errors.New("tunnel session closed during the call")
	}
	return &pb.DeviceResult{CallId: call.CallId, Class: pb.ResultClass_DONE, HttpStatus: uint32(r.Status), Body: r.Body}, nil
}

func (c *carriers) set(f func(c *carriers)) {
	c.mu.Lock()
	f(c)
	c.mu.Unlock()
}

func (c *carriers) sentKey(m pb.DeviceMethod) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, call := range c.relayed {
		if call.GetMethod() == m {
			return hex.EncodeToString(call.GetIdempotencyKey())
		}
	}
	return ""
}

// useDevAPI runs the harness engine on the agent's device API client.
func useDevAPI(t *testing.T, h *harness) *carriers {
	t.Helper()
	c := &carriers{api: h.api}
	byRoute := map[string]pb.DeviceMethod{}
	for m, r := range wire.DeviceRoutes {
		byRoute[r.Method+" "+r.Path] = m
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		down := c.httpsDown
		c.httpsKeys = append(c.httpsKeys, r.Header.Get("Idempotency-Key"))
		c.mu.Unlock()
		if down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp, err := c.api.Do(r.Context(), Request{Method: byRoute[r.Method+" "+r.URL.Path], Key: r.Header.Get("Idempotency-Key"), Body: b})
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
	}))
	t.Cleanup(srv.Close)
	caller, err := devicecall.New(devicecall.Config{Client: srv.Client(), Version: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("appsync device"))
	dc, err := devapi.New(devapi.Config{Caller: caller, Origin: func() string { return srv.URL },
		Key: func() crypto.Signer { return ed25519.NewKeyFromSeed(seed[:]) }, Stream0: c})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{Store: h.st, Carrier: dc, Now: h.clk.Now, Rand: h.e.cfg.Rand})
	if err != nil {
		t.Fatal(err)
	}
	h.e = e
	return c
}

// The session drops after the device API registered the app: the call goes
// over HTTPS under the same key and gets the stored answer, so the register
// ran once, its answer was applied and the outbox is empty.
func TestSessionDropMidRegisterRunsOnce(t *testing.T) {
	a := app("Media", "192.168.1.20", 8096)
	h := newHarness(t, a)
	c := useDevAPI(t, h)
	c.set(func(c *carriers) { c.dropAfter = pb.DeviceMethod_REGISTER_APPS })
	h.settle(20)
	apps := registeredOn(t, h.api, 1)
	if apps[0].LocalID != a.LocalID || h.target(a.LocalID).ServerServiceID != apps[0].ID {
		t.Fatalf("server %+v local %+v", apps, h.target(a.LocalID))
	}
	key := c.sentKey(pb.DeviceMethod_REGISTER_APPS)
	c.mu.Lock()
	keys := c.httpsKeys
	c.mu.Unlock()
	if key == "" || len(keys) != 1 || keys[0] != key {
		t.Fatalf("HTTPS resend %v, stream 0 key %s", keys, key)
	}
	if n := h.api.executed[key]; n != 1 {
		t.Fatalf("register ran %d times", n)
	}
	if s := h.e.Status(); s.OutboxDepth != 0 || s.LastResult != ResultOK {
		t.Fatalf("status %+v", s)
	}
}

// With no session and HTTPS failing, the call stays queued under its key,
// survives a restart and runs once when a carrier is back.
func TestQueuedCallSurvivesBothCarriersDown(t *testing.T) {
	a := app("Media", "192.168.1.20", 8096)
	h := newHarness(t, a)
	c := useDevAPI(t, h)
	h.steps(1) // the first list, on stream 0
	c.set(func(c *carriers) { c.edgeDown, c.httpsDown = true, true })
	h.steps(3)
	s := h.e.Status()
	if s.OutboxDepth != 1 || len(h.api.live()) != 0 || h.target(a.LocalID) == nil {
		t.Fatalf("status %+v", s)
	}
	key := h.e.box.Calls[0].Key
	h.restart()
	c = useDevAPI(t, h)
	h.settle(20)
	registeredOn(t, h.api, 1)
	if h.api.executed[key] != 1 || c.sentKey(pb.DeviceMethod_REGISTER_APPS) != key {
		t.Fatalf("queued call ran %d times; sent under %q, queued %q", h.api.executed[key], c.sentKey(pb.DeviceMethod_REGISTER_APPS), key)
	}
}

// UNAVAILABLE on stream 0 and a 503 over HTTPS change nothing locally.
func TestUnknownOutcomeChangesNothing(t *testing.T) {
	a := app("Media", "192.168.1.20", 8096)
	h := newHarness(t, a)
	c := useDevAPI(t, h)
	h.settle(20)
	before := h.st.State()
	h.api.ownerDelete(a.LocalID)
	c.set(func(c *carriers) { c.httpsDown = true })
	h.api.push(func(Request) (Response, error, bool, bool) { return Response{}, errors.New("relay down"), true, false })
	h.clk.Add(DefaultListEvery)
	h.steps(3)
	after := h.st.State()
	if len(after.Targets) != len(before.Targets) || after.Targets[0].ServerServiceID != before.Targets[0].ServerServiceID {
		t.Fatalf("local state changed: %+v", after.Targets)
	}
}
