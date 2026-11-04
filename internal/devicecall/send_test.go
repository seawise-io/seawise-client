package devicecall

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/seawise/client/internal/protocol"
)

func TestSendLargeAnswerCap(t *testing.T) {
	for _, size := range []int{MaxLargeAnswer, MaxLargeAnswer + 1} {
		c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", size)))
		})
		a, err := c.Send(context.Background(), Request{Key: testKey, Origin: srv.URL, Method: http.MethodGet, Path: "/x", MaxAnswer: MaxLargeAnswer})
		if (err != nil) != (size > MaxLargeAnswer) || (err == nil && len(a.Body) != size) {
			t.Fatal(size, err)
		}
		if size > MaxLargeAnswer && !errors.Is(err, ErrAnswerTooLarge) {
			t.Fatal(err)
		}
	}
}

func TestSendDefaultsToSmallCap(t *testing.T) {
	c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", MaxAnswer+1)))
	})
	if _, err := c.Send(context.Background(), Request{Key: testKey, Origin: srv.URL, Method: http.MethodGet, Path: "/x"}); !errors.Is(err, ErrAnswerTooLarge) {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), Request{Key: testKey, Origin: srv.URL, Method: http.MethodGet, Path: "/x", MaxAnswer: MaxLargeAnswer + 1}); err == nil {
		t.Fatal("cap above the largest answer accepted")
	}
}

func TestSendMarksARepeatedChallenge(t *testing.T) {
	c, srv, s := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", nonceA)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","code":"use_dpop_nonce"}`))
	})
	a, err := c.Send(context.Background(), Request{Key: testKey, Origin: srv.URL, Method: http.MethodPost, Path: "/x", Body: []byte(`{}`)})
	if err != nil || a.Status != http.StatusUnauthorized || !a.NonceChallenge || s.n() != 2 {
		t.Fatal(a, err, s.n())
	}
}

func TestSendChallengeWithoutNonceIsMarkedNotRetried(t *testing.T) {
	c, srv, s := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	a, err := c.Send(context.Background(), Request{Key: testKey, Origin: srv.URL, Method: http.MethodGet, Path: "/x"})
	if err != nil || !a.NonceChallenge || s.n() != 1 {
		t.Fatal(a, err, s.n())
	}
}

func TestOtherRefusalIsNoChallenge(t *testing.T) {
	c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", nonceA)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_proof","code":"replayed"}`))
	})
	a, err := c.Send(context.Background(), Request{Key: testKey, Origin: srv.URL, Method: http.MethodGet, Path: "/x"})
	if err != nil || a.NonceChallenge {
		t.Fatal(a, err)
	}
	for _, st := range []int{http.StatusOK, http.StatusForbidden} {
		if Challenged(st, "", []byte(`{"error":"use_dpop_nonce"}`)) != (st == http.StatusUnauthorized) {
			t.Fatal(st)
		}
	}
	if !Challenged(http.StatusUnauthorized, `DPoP error="use_dpop_nonce"`, nil) || !Challenged(http.StatusUnauthorized, "", []byte(`{"error":"use_dpop_nonce"}`)) {
		t.Fatal("challenge not seen")
	}
}

func TestProofUsesTheSharedNonce(t *testing.T) {
	c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", nonceB)
	})
	p, err := c.Proof(testKey, http.MethodPost, "https://api.example/device/v2/apps", []byte(`{"a":1}`))
	if err != nil || claimsOf(t, p).Nonce != "none" {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	p2, err := c.Proof(testKey, http.MethodPost, "https://api.example/device/v2/apps", []byte(`{"a":1}`))
	cl := claimsOf(t, p2)
	if err != nil || cl.Nonce != nonceB || cl.HTM != http.MethodPost || cl.HTU != "https://api.example/device/v2/apps" || cl.IAT != 1_800_000_000 {
		t.Fatal(err, cl)
	}
	if claimsOf(t, p).JTI == cl.JTI {
		t.Fatal("jti reused")
	}
	c.KeepNonce(nonceA)
	if claimsOf(t, mustProof(t, c)).Nonce != nonceA {
		t.Fatal("kept nonce not used")
	}
	if _, err := c.Proof(nil, http.MethodGet, "https://api.example/x", nil); err == nil {
		t.Fatal("proof without a key")
	}
}

func mustProof(t *testing.T, c *Caller) string {
	t.Helper()
	p, err := c.Proof(testKey, http.MethodGet, "https://api.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func claimsOf(t *testing.T, proof string) protocol.DPoPClaims {
	t.Helper()
	r := &http.Request{Header: http.Header{"Dpop": {proof}}}
	m := proofClaims(t, r)
	return protocol.DPoPClaims{HTM: m["htm"].(string), HTU: m["htu"].(string), Nonce: m["nonce"].(string), JTI: m["jti"].(string), IAT: m["iat"].(int64)}
}
