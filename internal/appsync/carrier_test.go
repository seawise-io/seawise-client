package appsync

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

func testKey() crypto.Signer {
	seed := sha256.Sum256([]byte("appsync-device"))
	return ed25519.NewKeyFromSeed(seed[:])
}

type seen struct {
	method, path, key, proof, ctype string
	body                            []byte
}

func carrierServer(t *testing.T, handle func(n int, w http.ResponseWriter, r *http.Request)) (*httptest.Server, *[]seen) {
	t.Helper()
	var mu sync.Mutex
	var reqs []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, seen{r.Method, r.URL.RequestURI(), r.Header.Get("Idempotency-Key"), r.Header.Get("DPoP"), r.Header.Get("Content-Type"), b})
		n := len(reqs)
		mu.Unlock()
		handle(n, w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func newCarrier(srv *httptest.Server) *HTTPS {
	return &HTTPS{Origin: srv.URL, Key: testKey, Client: srv.Client(), Version: "2.0.0", Now: func() time.Time { return time.Unix(1700000000, 0) }}
}

func TestHTTPSFreshProofPerAttemptWithNewestNonce(t *testing.T) {
	srv, reqs := carrierServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
		switch n {
		case 1:
			w.Header().Set("DPoP-Nonce", "nonce-1")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","code":"use_dpop_nonce"}`))
		default:
			w.Header().Set("DPoP-Nonce", "nonce-"+string(rune('0'+n)))
			_, _ = w.Write([]byte(`{"items":[]}`))
		}
	})
	c := newCarrier(srv)
	req := Request{Method: pb.DeviceMethod_REGISTER_APPS, Key: strings.Repeat("ab", 16), Body: []byte(`{"apps":[]}`)}
	r1, err := c.Do(context.Background(), req)
	if err != nil || r1.Status != 401 || !r1.NonceChallenge {
		t.Fatalf("%+v %v", r1, err)
	}
	r2, err := c.Do(context.Background(), req)
	if err != nil || r2.Status != 200 {
		t.Fatalf("%+v %v", r2, err)
	}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	rs := *reqs
	jtis := map[string]bool{}
	for i, s := range rs {
		if s.method != "POST" || s.path != "/device/v2/apps" || s.key != req.Key || string(s.body) != string(req.Body) || s.ctype != "application/json" {
			t.Fatalf("request %d: %+v", i, s)
		}
		wantNonce := []string{"none", "nonce-1", "nonce-2"}[i]
		res, err := protocol.VerifyDPoP(s.proof, protocol.DPoPRequest{Method: "POST", URL: srv.URL + "/device/v2/apps", Body: s.body},
			func(n string) bool { return n == wantNonce }, func(string, string) bool { return true })
		if err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if jtis[res.Claims.JTI] {
			t.Fatal("jti reused across attempts")
		}
		jtis[res.Claims.JTI] = true
	}
}

func TestHTTPSListAndHealthCarryNoKey(t *testing.T) {
	srv, reqs := carrierServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	c := newCarrier(srv)
	if _, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod_LIST_APPS}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod_REPORT_HEALTH, Body: []byte(`{"apps":[]}`)}); err != nil {
		t.Fatal(err)
	}
	rs := *reqs
	if rs[0].method != "GET" || rs[0].path != "/device/v2/apps" || rs[0].key != "" || len(rs[0].body) != 0 {
		t.Fatalf("%+v", rs[0])
	}
	if rs[1].method != "POST" || rs[1].path != "/device/v2/health" || rs[1].key != "" {
		t.Fatalf("%+v", rs[1])
	}
}

func TestHTTPSNoRedirects(t *testing.T) {
	other, otherReqs := carrierServer(t, func(int, http.ResponseWriter, *http.Request) {})
	srv, _ := carrierServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/device/v2/apps", http.StatusTemporaryRedirect)
	})
	c := newCarrier(srv)
	r, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod_LIST_APPS})
	if err != nil || r.Status != http.StatusTemporaryRedirect || len(*otherReqs) != 0 {
		t.Fatalf("%+v %v %d", r, err, len(*otherReqs))
	}
}

func TestHTTPSAnswerTooLarge(t *testing.T) {
	srv, _ := carrierServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxAnswer+1)))
	})
	if _, err := newCarrier(srv).Do(context.Background(), Request{Method: pb.DeviceMethod_LIST_APPS}); err == nil {
		t.Fatal("oversized answer accepted")
	}
}

func TestHTTPSRetryAfterAndInvalidNonce(t *testing.T) {
	srv, reqs := carrierServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			w.Header().Set("DPoP-Nonce", "bad nonce \"")
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	})
	c := newCarrier(srv)
	r, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod_LIST_APPS})
	if err != nil || r.Status != 429 || r.RetryAfter != 7*time.Second {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod_LIST_APPS}); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.VerifyDPoP((*reqs)[1].proof, protocol.DPoPRequest{Method: "GET", URL: srv.URL + "/device/v2/apps"},
		func(n string) bool { return n == "none" }, func(string, string) bool { return true }); err != nil {
		t.Fatal("invalid nonce was kept:", err)
	}
}

func TestHTTPSNoKeyOrUnknownMethod(t *testing.T) {
	srv, reqs := carrierServer(t, func(int, http.ResponseWriter, *http.Request) {})
	c := newCarrier(srv)
	c.Key = func() crypto.Signer { return nil }
	if _, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod_LIST_APPS}); err == nil {
		t.Fatal("sent without a key")
	}
	c.Key = testKey
	if _, err := c.Do(context.Background(), Request{Method: pb.DeviceMethod(99)}); err == nil {
		t.Fatal("unknown method sent")
	}
	if len(*reqs) != 0 {
		t.Fatal("request left")
	}
}
