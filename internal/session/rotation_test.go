package session

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

func pendingKID() string { return protocol.KeyID(pubOf(seedKey("pending"))) }

func stateFor(t *testing.T, kid, nonce, device string) string {
	return sign(t, "control", protocol.TypState, map[string]any{"server_id": testServer, "key_id": kid,
		"time": 1700000001, "nonce": nonce, "device_status": device, "account_status": "active"})
}

func rotationHarness(t *testing.T) (*harness, chan struct{}) {
	committed := make(chan struct{}, 1)
	h := newHarness(t, func(c *Config) {
		c.Pending = func() crypto.Signer { return seedKey("pending") }
		c.CommitRotation = func(string) error { committed <- struct{}{}; return nil }
	})
	return h, committed
}

func keyRotated(c *fakeConn) {
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_KEY_ROTATED, DeadlineMs: 5000}}}
}

func TestKeyRotatedCommitsOnlyAfterSignedProof(t *testing.T) {
	h, committed := rotationHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateFor(t, pendingKID(), n, "active"), flagsDoc(t, 2, "on"))
	})
	keyRotated(h.up(h.dial()))
	select {
	case <-committed:
	case <-time.After(5 * time.Second):
		t.Fatal("pending key not committed after a signed proof")
	}
	h.wait("flags from the proof", func(s Status) bool { return s.FlagsGeneration == 2 })
	h.hb.mu.Lock()
	hdr, body := h.hb.headers[len(h.hb.headers)-1], h.hb.bodies[len(h.hb.bodies)-1]
	h.hb.mu.Unlock()
	res, err := protocol.VerifyDPoP(hdr.Get("DPoP"), protocol.DPoPRequest{Method: "POST", URL: h.hb.srv.URL + HeartbeatPath, Body: body},
		func(string) bool { return true }, func(string, string) bool { return true })
	if err != nil || res.KeyID != pendingKID() {
		t.Fatalf("proof: %v %v", res, err)
	}
}

func TestKeyRotatedWithoutProofKeepsOldKey(t *testing.T) {
	for name, answer := range map[string]func(t *testing.T, n string) (int, string){
		"unavailable": func(t *testing.T, n string) (int, string) { return http.StatusServiceUnavailable, "" },
		"old key": func(t *testing.T, n string) (int, string) {
			return http.StatusOK, answerJSON(stateFor(t, deviceKeyID(), n, "active"), "")
		},
		"pending not active": func(t *testing.T, n string) (int, string) {
			return http.StatusOK, answerJSON(stateFor(t, pendingKID(), n, "pending"), "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, committed := rotationHarness(t)
			h.hb.set(func(n string) (int, string) { return answer(t, n) })
			keyRotated(h.up(h.dial()))
			<-h.hb.nonces
			select {
			case <-committed:
				t.Fatal("committed on the edge's word")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// rotatingDevice is a keystore whose rotation the server already accepted:
// the old key is revoked, the pending key active.
type rotatingDevice struct {
	mu        sync.Mutex
	pending   crypto.Signer
	committed string
	proofs    int
}

func (d *rotatingDevice) Pending() crypto.Signer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pending
}

func (d *rotatingDevice) Commit(kid string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil || protocol.KeyID(d.pending.Public().(ed25519.PublicKey)) != kid {
		return errors.New("pending key is not the key named")
	}
	d.committed, d.pending = kid, nil
	return nil
}

func (d *rotatingDevice) isCommitted() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.committed != ""
}

func rotatingHarness(t *testing.T, d *rotatingDevice) *harness {
	h := newHarness(t, func(c *Config) {
		c.Pending = d.Pending
		c.CommitRotation = d.Commit
		c.KeyID = func() string {
			if d.isCommitted() {
				return pendingKID()
			}
			return deviceKeyID()
		}
	})
	return h
}

func TestFailedProofDoesNotStrandRevokedDevice(t *testing.T) {
	d := &rotatingDevice{pending: seedKey("pending")}
	h := rotatingHarness(t, d)
	h.hb.setKeyed(func(n, kid string) (int, string) {
		if kid == pendingKID() {
			d.mu.Lock()
			d.proofs++
			first := d.proofs == 1
			d.mu.Unlock()
			if first {
				return http.StatusServiceUnavailable, ""
			}
			return http.StatusOK, answerJSON(stateFor(t, pendingKID(), n, "active"), "")
		}
		return http.StatusOK, answerJSON(stateFor(t, deviceKeyID(), n, "revoked"), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	for i := 0; i < 40 && !d.isCommitted(); i++ {
		h.advance(30 * time.Second)
		h.settle()
	}
	if !d.isCommitted() {
		t.Fatalf("pending key never committed: %+v", h.m.Status())
	}
	h.up(h.dial())
	if s := h.m.Status(); s.Hold != "" || !s.Up {
		t.Fatalf("stranded: %+v", s)
	}
}

func TestKeyRotatedFloodSendsOneProof(t *testing.T) {
	d := &rotatingDevice{pending: seedKey("pending")}
	h := rotatingHarness(t, d)
	h.hb.set(func(string) (int, string) { return http.StatusServiceUnavailable, "" })
	c := h.up(h.dial())
	for i := 0; i < 200; i++ {
		keyRotated(c)
	}
	h.settle()
	time.Sleep(100 * time.Millisecond)
	h.hb.mu.Lock()
	n := len(h.hb.headers)
	h.hb.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d proofs for 200 drains", n)
	}
}

func TestReplacedPendingKeyNotCommitted(t *testing.T) {
	d := &rotatingDevice{pending: seedKey("pending")}
	h := rotatingHarness(t, d)
	h.hb.setKeyed(func(n, kid string) (int, string) {
		d.mu.Lock()
		d.pending = seedKey("another")
		d.mu.Unlock()
		return http.StatusOK, answerJSON(stateFor(t, kid, n, "active"), "")
	})
	keyRotated(h.up(h.dial()))
	<-h.hb.nonces
	h.settle()
	if d.isCommitted() {
		t.Fatal("committed a key that is no longer pending")
	}
}

func TestCommitRedialsAtOnce(t *testing.T) {
	d := &rotatingDevice{pending: seedKey("pending")}
	h := rotatingHarness(t, d)
	h.hb.setKeyed(func(n, kid string) (int, string) {
		if kid == pendingKID() {
			return http.StatusOK, answerJSON(stateFor(t, pendingKID(), n, "active"), "")
		}
		return http.StatusOK, answerJSON(stateFor(t, deviceKeyID(), n, "revoked"), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	h.settle()
	if !d.isCommitted() {
		t.Fatal("not committed")
	}
	h.dial()
}

func TestRotationProofBackoff(t *testing.T) {
	d := &rotatingDevice{pending: seedKey("pending")}
	h := rotatingHarness(t, d)
	h.hb.set(func(string) (int, string) { return http.StatusServiceUnavailable, "" })
	keyRotated(h.up(h.dial()))
	<-h.hb.nonces
	// Rand returns n-1: each wait is the backoff step plus 30 s of jitter.
	for _, step := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute} {
		h.settle()
		h.advance(step + 29*time.Second)
		select {
		case <-h.hb.nonces:
			t.Fatalf("proof before %s", step+30*time.Second)
		case <-time.After(20 * time.Millisecond):
		}
		h.advance(time.Second)
		select {
		case <-h.hb.nonces:
		case <-time.After(5 * time.Second):
			t.Fatalf("no proof after %s", step+30*time.Second)
		}
	}
}

func TestRevokedHoldWaitsForTheProof(t *testing.T) {
	d := &rotatingDevice{pending: seedKey("pending")}
	h := rotatingHarness(t, d)
	release := make(chan struct{})
	h.hb.setKeyed(func(n, kid string) (int, string) {
		if kid == pendingKID() {
			<-release
			return http.StatusServiceUnavailable, ""
		}
		return http.StatusOK, answerJSON(stateFor(t, deviceKeyID(), n, "revoked"), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	<-h.hb.nonces
	<-h.hb.nonces
	h.settle()
	if s := h.m.Status(); s.Hold != "" {
		close(release)
		t.Fatalf("held before the proof answered: %+v", s)
	}
	close(release)
	h.wait("held after the failed proof", func(s Status) bool { return s.Hold == "revoked" })
}
