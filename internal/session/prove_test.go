package session

import (
	"crypto"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestProveRotationCommitsOnceOnSignedProof(t *testing.T) {
	var mu sync.Mutex
	pending := crypto.Signer(seedKey("pending"))
	committed := make(chan struct{}, 2)
	h := newHarness(t, func(c *Config) {
		c.Pending = func() crypto.Signer { mu.Lock(); defer mu.Unlock(); return pending }
		c.CommitRotation = func(string) error {
			mu.Lock()
			pending = nil
			mu.Unlock()
			committed <- struct{}{}
			return nil
		}
	})
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateFor(t, pendingKID(), n, "active"), "")
	})
	if err := h.m.ProveRotation(); err != nil {
		t.Fatal(err)
	}
	if err := h.m.ProveRotation(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("not committed after a signed proof")
	}
	select {
	case <-committed:
		t.Fatal("committed twice")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProveRotationBare200NeverCommits(t *testing.T) {
	for name, body := range map[string]string{"empty": `{}`, "no state": `{"data":{}}`, "plain": `ok`} {
		t.Run(name, func(t *testing.T) {
			h, committed := rotationHarness(t)
			h.hb.set(func(string) (int, string) { return http.StatusOK, body })
			if err := h.m.ProveRotation(); err != nil {
				t.Fatal(err)
			}
			<-h.hb.nonces
			select {
			case <-committed:
				t.Fatal("committed on a bare 200")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestProveRotationWithoutPendingKey(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Pending = func() crypto.Signer { return nil }
		c.CommitRotation = func(string) error { return nil }
	})
	if err := h.m.ProveRotation(); !errors.Is(err, ErrNoPendingKey) {
		t.Fatalf("err %v", err)
	}
}
