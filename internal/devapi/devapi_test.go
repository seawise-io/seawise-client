package devapi

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/devicecall"
)

func unavailable(retryMs uint32) func(*pb.DeviceCall) (*pb.DeviceResult, bool, error) {
	return func(c *pb.DeviceCall) (*pb.DeviceResult, bool, error) {
		return &pb.DeviceResult{CallId: c.CallId, Class: pb.ResultClass_UNAVAILABLE, RetryAfterMs: retryMs}, true, nil
	}
}

// executedThenLost runs the call at the device API, then the session
// drops before the result reaches the agent.
func executedThenLost(e *fakeEdge) func(*pb.DeviceCall) (*pb.DeviceResult, bool, error) {
	return func(c *pb.DeviceCall) (*pb.DeviceResult, bool, error) {
		e.relay(c)
		return nil, true, errors.New("tunnel session closed during the call")
	}
}

func TestStreamZeroWhenASessionIsUp(t *testing.T) {
	e := newEnv(t)
	e.api.setNonce("none")
	a, err := e.c.Do(context.Background(), registerCall())
	if err != nil || a.Status != 200 || !a.Relayed {
		t.Fatal(a, err)
	}
	calls := e.edge.sent()
	if len(calls) != 1 || hex.EncodeToString(calls[0].GetIdempotencyKey()) != key1 || calls[0].GetMethod() != pb.DeviceMethod_REGISTER_APPS ||
		calls[0].GetPathSuffix() != "" || !bytes.Equal(calls[0].GetBody(), registerCall().Body) {
		t.Fatal(calls)
	}
	reqs := e.api.requests()
	if len(reqs) != 1 || !reqs[0].relayed || reqs[0].path != "/device/v2/apps" || reqs[0].method != http.MethodPost {
		t.Fatal(reqs)
	}
}

func TestHTTPSWithoutASession(t *testing.T) {
	for _, name := range []string{"no session", "no stream 0"} {
		var e *env
		if name == "no stream 0" {
			e = newEnv(t, func(c *Config) { c.Stream0 = nil })
		} else {
			e = newEnv(t)
			e.edge.setDown(true)
		}
		e.api.setNonce("none")
		a, err := e.c.Do(context.Background(), registerCall())
		if err != nil || a.Status != 200 || a.Relayed {
			t.Fatal(name, a, err)
		}
		reqs := e.api.requests()
		if len(reqs) != 1 || reqs[0].relayed || reqs[0].key != key1 || reqs[0].ctype != "application/json" || reqs[0].userAgent != "seawise-agent/2.0.0" {
			t.Fatal(name, reqs)
		}
	}
}

func TestDirectCallsSkipStreamZero(t *testing.T) {
	e := newEnv(t)
	a, err := e.c.Do(context.Background(), Call{Method: pb.DeviceMethod_LIST_APPS, Direct: true})
	if err != nil || a.Relayed || a.Status != 200 || len(e.edge.sent()) != 0 {
		t.Fatal(a, err)
	}
	if r := e.api.requests(); len(r) != 2 || r[1].idempotencyPresent || r[1].method != http.MethodGet || r[1].ctype != "" {
		t.Fatal(r)
	}
}

// UNAVAILABLE means the outcome is unknown: the same call (key and body)
// goes over HTTPS with a fresh proof.
func TestUnavailableFallsBackWithTheSameKeyAndBody(t *testing.T) {
	e := newEnv(t)
	e.edge.push(unavailable(1000))
	a, err := e.c.Do(context.Background(), registerCall())
	if err != nil || a.Status != 200 || a.Relayed {
		t.Fatal(a, err)
	}
	reqs := e.api.requests()
	last := reqs[len(reqs)-1]
	if last.relayed || last.key != key1 || !bytes.Equal(last.body, registerCall().Body) {
		t.Fatal(reqs)
	}
	jtis := map[string]bool{}
	for _, r := range reqs {
		if jtis[r.jti] {
			t.Fatal("proof reused")
		}
		jtis[r.jti] = true
	}
}

// The session drops after the device API ran the call: the HTTPS resend
// under the same key gets the stored answer, so the call takes effect
// once and its answer is not lost.
func TestSessionLostMidCallIsNeitherLostNorDuplicated(t *testing.T) {
	e := newEnv(t)
	n := 0
	e.api.answer = func(r request) (int, []byte, string) {
		n++
		return 200, []byte(`{"run":` + string(rune('0'+n)) + `}`), ""
	}
	_, err := e.c.Do(context.Background(), Call{Method: pb.DeviceMethod_LIST_APPS})
	if err != nil {
		t.Fatal(err)
	}
	e.edge.push(executedThenLost(e.edge))
	a, err := e.c.Do(context.Background(), registerCall())
	if err != nil || a.Status != 200 || a.Relayed {
		t.Fatal(a, err)
	}
	if got := e.api.executed("POST /device/v2/apps " + key1); got != 1 {
		t.Fatalf("executed %d times", got)
	}
	if string(a.Body) != `{"run":2}` {
		t.Fatalf("answer %s is not the stored one", a.Body)
	}
	// The next retry (a new session) replays the same answer again.
	b, err := e.c.Do(context.Background(), registerCall())
	if err != nil || !b.Relayed || string(b.Body) != `{"run":2}` || e.api.executed("POST /device/v2/apps "+key1) != 1 {
		t.Fatal(b, err)
	}
}

// The session drops before the call reached the device API: HTTPS runs it
// once.
func TestSessionLostBeforeTheCallRuns(t *testing.T) {
	e := newEnv(t)
	e.edge.push(func(*pb.DeviceCall) (*pb.DeviceResult, bool, error) {
		return nil, true, errors.New("tunnel session closed during the call")
	})
	a, err := e.c.Do(context.Background(), registerCall())
	if err != nil || a.Status != 200 || e.api.executed("POST /device/v2/apps "+key1) != 1 {
		t.Fatal(a, err)
	}
}

// Both carriers fail: the error says the outcome is unknown and the
// caller retries with the same key later.
func TestBothCarriersDown(t *testing.T) {
	e := newEnv(t)
	e.edge.push(unavailable(1000))
	e.api.srv.Close()
	if _, err := e.c.Do(context.Background(), registerCall()); err == nil {
		t.Fatal("no error")
	}
}

func TestCancelledCallDoesNotFallBack(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.edge.push(func(*pb.DeviceCall) (*pb.DeviceResult, bool, error) {
		cancel()
		return nil, true, context.Canceled
	})
	if _, err := e.c.Do(ctx, registerCall()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, r := range e.api.requests() {
		if !r.relayed {
			t.Fatal("sent over HTTPS after the call was cancelled")
		}
	}
}

func TestNonceChallengeOnStreamZero(t *testing.T) {
	e := newEnv(t)
	a, err := e.c.Do(context.Background(), registerCall())
	if err != nil || a.Status != 200 || !a.Relayed || a.NonceChallenge {
		t.Fatal(a, err)
	}
	calls := e.edge.sent()
	if len(calls) != 2 || !bytes.Equal(calls[0].GetIdempotencyKey(), calls[1].GetIdempotencyKey()) || calls[0].GetDpop() == calls[1].GetDpop() {
		t.Fatal("nonce retry must keep the key and sign a fresh proof", calls)
	}
	if r := e.api.requests(); r[1].nonce != e.api.current() {
		t.Fatal("retry without the server nonce")
	}
}

// A second challenge is the caller's to handle, as over HTTPS.
func TestRepeatedChallengeIsReturned(t *testing.T) {
	for _, relay := range []bool{true, false} {
		e := newEnv(t)
		e.edge.setDown(!relay)
		e.api.answer = func(request) (int, []byte, string) { return 200, nil, "" }
		e.api.mu.Lock()
		e.api.challenge = true
		e.api.mu.Unlock()
		a, err := e.c.Do(context.Background(), registerCall())
		if err != nil || a.Status != 401 || !a.NonceChallenge || a.Relayed != relay {
			t.Fatal(relay, a, err)
		}
		if n := len(e.api.requests()); n != 2 {
			t.Fatal(relay, n, "attempts")
		}
	}
}

// A nonce learned on one carrier is used on the other.
func TestNonceSharedAcrossCarriers(t *testing.T) {
	e := newEnv(t)
	if _, err := e.c.Do(context.Background(), registerCall()); err != nil {
		t.Fatal(err)
	}
	e.edge.setDown(true)
	if _, err := e.c.Do(context.Background(), Call{Method: pb.DeviceMethod_LIST_APPS}); err != nil {
		t.Fatal(err)
	}
	reqs := e.api.requests()
	if len(reqs) != 3 || reqs[2].relayed || reqs[2].nonce != e.api.current() {
		t.Fatal("HTTPS did not use the nonce learned on stream 0", reqs)
	}
}

// Whatever the device API answers reaches the caller the same way on both
// carriers; only Relayed differs.
func TestSameAnswersOnBothCarriers(t *testing.T) {
	answers := []struct {
		status int
		body   string
		retry  string
	}{
		{200, `{"items":[]}`, ""},
		{401, `{"error":"invalid_proof","code":"replayed"}`, ""},
		{401, `{"error":"invalid_proof","code":"key_revoked"}`, ""},
		{403, `{"error":"limit_reached"}`, ""},
		{409, `{"error":"name_taken","index":0,"local_id":"a"}`, ""},
		{413, `{"error":"list_too_large","apps":1200}`, ""},
		{429, `{"error":"rate_limited"}`, "7"},
		{503, `{"error":"Service unavailable"}`, "1"},
	}
	for _, want := range answers {
		var got [2]Answer
		for i, relay := range []bool{true, false} {
			e := newEnv(t)
			e.edge.setDown(!relay)
			e.api.setNonce("none")
			e.api.answer = func(request) (int, []byte, string) { return want.status, []byte(want.body), want.retry }
			a, err := e.c.Do(context.Background(), registerCall())
			if err != nil || a.Relayed != relay {
				t.Fatal(want.status, relay, a, err)
			}
			a.Relayed = false
			got[i] = a
		}
		if got[0].Status != want.status || string(got[0].Body) != want.body || got[0].Status != got[1].Status ||
			!bytes.Equal(got[0].Body, got[1].Body) || got[0].RetryAfter != got[1].RetryAfter || got[0].NonceChallenge != got[1].NonceChallenge {
			t.Fatalf("%d: stream 0 %+v, HTTPS %+v", want.status, got[0], got[1])
		}
		if want.retry != "" && got[0].RetryAfter == 0 {
			t.Fatalf("%d: Retry-After lost", want.status)
		}
	}
}

func TestBodyOverTheStreamZeroCapGoesOverHTTPS(t *testing.T) {
	e := newEnv(t)
	big := Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: key1, Body: []byte(`{"apps":"` + strings.Repeat("a", wire.MaxDeviceBody) + `"}`)}
	a, err := e.c.Do(context.Background(), big)
	if err != nil || a.Relayed || len(e.edge.sent()) != 0 {
		t.Fatal(a, err)
	}
	atCap := Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: "1123456789abcdef0123456789abcdef", Body: bytes.Repeat([]byte("a"), wire.MaxDeviceBody)}
	if a, err := e.c.Do(context.Background(), atCap); err != nil || !a.Relayed {
		t.Fatal("a body at the cap must ride stream 0", a, err)
	}
}

// Calls that are not queued get a fresh key per call on stream 0 (the
// wire needs one) and none over HTTPS, as before.
func TestUnqueuedCallsGetAFreshKey(t *testing.T) {
	e := newEnv(t)
	for range 2 {
		if _, err := e.c.Do(context.Background(), Call{Method: pb.DeviceMethod_LIST_APPS}); err != nil {
			t.Fatal(err)
		}
	}
	calls := e.edge.sent()
	if len(calls) != 3 {
		t.Fatal(len(calls))
	}
	if !bytes.Equal(calls[0].GetIdempotencyKey(), calls[1].GetIdempotencyKey()) {
		t.Fatal("the nonce retry changed the key")
	}
	if bytes.Equal(calls[1].GetIdempotencyKey(), calls[2].GetIdempotencyKey()) || bytes.Equal(calls[2].GetIdempotencyKey(), make([]byte, 16)) {
		t.Fatal("key reused across calls")
	}
	if len(calls[2].GetBody()) != 0 {
		t.Fatal("list carries a body")
	}
}

func TestRefusedInput(t *testing.T) {
	e := newEnv(t)
	bad := []Call{
		{Method: pb.DeviceMethod_METHOD_UNSPECIFIED},
		{Method: pb.DeviceMethod(99)},
		{Method: pb.DeviceMethod_REGISTER_APPS, Key: strings.ToUpper(key1)},
		{Method: pb.DeviceMethod_REGISTER_APPS, Key: key1[:31]},
		{Method: pb.DeviceMethod_REGISTER_APPS, Key: key1 + "0"},
		{Method: pb.DeviceMethod_REGISTER_APPS, Key: "0123456789abcdef0123456789abcdeg"},
	}
	for _, c := range bad {
		if _, err := e.c.Do(context.Background(), c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	nokey := newEnv(t, func(c *Config) { c.Key = func() crypto.Signer { return nil } })
	if _, err := nokey.c.Do(context.Background(), registerCall()); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
	plain := newEnv(t, func(c *Config) { c.Origin = func() string { return "http://api.example" } })
	if _, err := plain.c.Do(context.Background(), registerCall()); !errors.Is(err, devicecall.ErrInsecureOrigin) {
		t.Fatal(err)
	}
	if len(e.edge.sent())+len(e.api.requests())+len(nokey.edge.sent())+len(plain.edge.sent()) != 0 {
		t.Fatal("refused calls were sent")
	}
}

func TestNewChecksConfig(t *testing.T) {
	e := newEnv(t)
	good := Config{Caller: e.caller, Origin: e.api.origin, Key: func() crypto.Signer { return deviceKey }}
	for _, f := range []func(*Config){
		func(c *Config) { c.Caller = nil },
		func(c *Config) { c.Origin = nil },
		func(c *Config) { c.Key = nil },
	} {
		c := good
		f(&c)
		if _, err := New(c); err == nil {
			t.Error("incomplete config accepted")
		}
	}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
}

func TestAnswerTooLarge(t *testing.T) {
	e := newEnv(t)
	e.edge.setDown(true)
	e.api.answer = func(request) (int, []byte, string) {
		return 200, bytes.Repeat([]byte(" "), devicecall.MaxLargeAnswer+1), ""
	}
	if _, err := e.c.Do(context.Background(), Call{Method: pb.DeviceMethod_LIST_APPS}); !errors.Is(err, ErrAnswerTooLarge) {
		t.Fatal(err)
	}
}

func TestRelayedRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.edge.push(func(c *pb.DeviceCall) (*pb.DeviceResult, bool, error) {
		return &pb.DeviceResult{CallId: c.CallId, Class: pb.ResultClass_DONE, HttpStatus: 503, RetryAfterMs: 2500}, true, nil
	})
	a, err := e.c.Do(context.Background(), registerCall())
	if err != nil || a.Status != 503 || a.RetryAfter != 2500*time.Millisecond || !a.Relayed {
		t.Fatal(a, err)
	}
}

type slowRelay struct{ left chan time.Duration }

func (s slowRelay) Relay(ctx context.Context, _ *pb.DeviceCall) (*pb.DeviceResult, error) {
	dl, _ := ctx.Deadline()
	s.left <- time.Until(dl)
	<-ctx.Done()
	return nil, ctx.Err()
}

// A stream 0 leg that never answers uses at most half the call's time, so
// the HTTPS resend still has the rest.
func TestStreamZeroLegLeavesTimeForHTTPS(t *testing.T) {
	e := newEnv(t)
	sr := slowRelay{left: make(chan time.Duration, 1)}
	c, err := New(Config{Caller: e.caller, Origin: e.api.origin, Key: func() crypto.Signer { return deviceKey }, Stream0: sr})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	a, err := c.Do(ctx, registerCall())
	if err != nil || a.Relayed || a.Status != 200 {
		t.Fatal(a, err)
	}
	if left := <-sr.left; left > 1100*time.Millisecond {
		t.Fatalf("stream 0 leg had %s of 2 s", left)
	}
	if d := time.Since(start); d > 1900*time.Millisecond {
		t.Fatal("HTTPS got no time", d)
	}
}

// Only a DONE result's nonce is kept.
func TestNonceKeptOnlyFromDone(t *testing.T) {
	e := newEnv(t)
	e.api.srv.Close()
	e.edge.push(func(c *pb.DeviceCall) (*pb.DeviceResult, bool, error) {
		return &pb.DeviceResult{CallId: c.CallId, Class: pb.ResultClass_UNAVAILABLE, DpopNonce: "n1.AAAAAQ.c2VydmVyLW5vbmNl", RetryAfterMs: 1000}, true, nil
	})
	_, _ = e.c.Do(context.Background(), registerCall())
	if e.caller.Nonce() == "n1.AAAAAQ.c2VydmVyLW5vbmNl" {
		t.Fatal("nonce kept from UNAVAILABLE")
	}
}
