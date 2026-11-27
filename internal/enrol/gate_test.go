package enrol

import (
	"net/http"
	"testing"

	"github.com/seawise/client/internal/store"
)

// No 1.x call may run from the moment enroll is sent until its outcome is
// stored; OnChange runs after the gate is released.
func TestEnrolHoldsTheLegacyGate(t *testing.T) {
	v := newEnv(t)
	var sent, freeDuringEnrol bool
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathEnroll {
			sent = true
			if v.gate.TryRLock() {
				freeDuringEnrol = true
				v.gate.RUnlock()
			}
		}
		v.fake.ServeHTTP(w, r)
	})
	freeInChange := false
	v.onChange = func() {
		if v.gate.TryRLock() {
			freeInChange = true
			v.gate.RUnlock()
		}
	}
	v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
	if !sent || freeDuringEnrol {
		t.Fatalf("enroll sent %v; 1.x calls allowed while it ran: %v", sent, freeDuringEnrol)
	}
	if !freeInChange {
		t.Fatal("gate still held in OnChange")
	}
	if !v.gate.TryLock() {
		t.Fatal("gate not released after enrolment")
	}
	v.gate.Unlock()
}

func TestEnrolReleasesTheGateOnHold(t *testing.T) {
	v := newEnv(t)
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathEnroll {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"already_enrolled"}`))
			return
		}
		v.fake.ServeHTTP(w, r)
	})
	v.run(20, func() bool { return v.holdReason() != "" })
	if v.holdReason() != store.HoldAlreadyEnrolled {
		t.Fatalf("hold %q", v.holdReason())
	}
	if !v.gate.TryLock() {
		t.Fatal("gate not released after a hold")
	}
	v.gate.Unlock()
}
