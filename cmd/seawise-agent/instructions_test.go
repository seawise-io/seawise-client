package main

import (
	"context"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seawise/client/internal/keyset"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/transport"
	"github.com/seawise/client/internal/visitor"
)

func pairedStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "synthetic-token"; return nil }); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000, APIURL: "https://api.seawise.io"}
		for _, id := range []string{"app1", "app2"} {
			s.Targets = append(s.Targets, store.Target{LocalID: id, Name: id, Host: "127.0.0.1", Port: 8080, Source: store.SourceLocal})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestDeleteAppExecutor(t *testing.T) {
	st := pairedStore(t)
	reconciled := 0
	ex := executors(st, func(context.Context) error { reconciled++; return nil })
	if err := ex.deleteApp(context.Background(), "app1"); err != nil {
		t.Fatal(err)
	}
	if ts := st.State().Targets; len(ts) != 1 || ts[0].LocalID != "app2" {
		t.Fatalf("targets %+v", ts)
	}
	// Idempotent: an app already gone is done.
	if err := ex.deleteApp(context.Background(), "app1"); err != nil {
		t.Fatal(err)
	}
	if reconciled != 2 {
		t.Fatalf("reconciled %d times", reconciled)
	}
}

func TestUnpairExecutor(t *testing.T) {
	st := pairedStore(t)
	reconciled := 0
	ex := executors(st, func(context.Context) error { reconciled++; return nil })
	for i := 0; i < 2; i++ {
		if err := ex.unpair(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if st.State().Account != nil || st.Secrets().FRPToken != "" {
		t.Fatal("still paired")
	}
	if reconciled != 2 {
		t.Fatalf("reconciled %d times", reconciled)
	}
}

// The key set's dial holds are the reasons the tunnel shows.
func TestKeySetHoldNames(t *testing.T) {
	if keyset.HoldMissing != transport.HoldKeySetMissing {
		t.Fatal("hold names differ")
	}
	var none *trust
	if none.current() != nil || none.hold() != keyset.HoldMissing {
		t.Fatal("no key set must hold dials")
	}
	if (&trust{}).hold() != keyset.HoldMissing {
		t.Fatal("unconfigured key set must hold dials")
	}
}

// The processor follows the paired server without a restart.
func TestInstructionsFollowTheAccount(t *testing.T) {
	st := pairedStore(t)
	h := newInstructions(nil, st, &trust{}, func(time.Time) bool { return false }, func(context.Context) error { return nil })
	p1, id1 := h.get()
	if p1 == nil || id1 != "7c9e6679-7425-40de-944b-e07fc1f90ae7" {
		t.Fatalf("paired: %v %q", p1, id1)
	}
	if p, _ := h.get(); p != p1 {
		t.Fatal("rebuilt without an account change")
	}
	_ = st.Update(func(s *store.State) error { s.Account = nil; return nil })
	if p, _ := h.get(); p != nil {
		t.Fatal("processor kept after unpairing")
	}
	other := "11111111-2222-4333-8444-555555555555"
	_ = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: other, FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000, APIURL: "https://api.seawise.io"}
		return nil
	})
	p2, id2 := h.get()
	if p2 == nil || p2 == p1 || id2 != other {
		t.Fatalf("re-paired: %v %q", p2, id2)
	}
	if h.status() == nil {
		t.Fatal("no status")
	}
}

// set_visitor_enforcement changes the paired server's mode, persisted per
// server; another pairing starts in observe.
func TestVisitorEnforcementFollowsTheAccount(t *testing.T) {
	st := pairedStore(t)
	h := newInstructions(nil, st, &trust{}, func(time.Time) bool { return false }, func(context.Context) error { return nil })
	if h.visitorMode() != visitor.Observe {
		t.Fatal("default is not observe")
	}
	set := setVisitorEnforcement(slog.New(slog.DiscardHandler), h.modeStore())
	if err := set(context.Background(), "enforce", 100); err != nil {
		t.Fatal(err)
	}
	if h.visitorMode() != visitor.Enforce {
		t.Fatal("mode not applied")
	}
	if err := set(context.Background(), "observe", 99); err != nil || h.visitorMode() != visitor.Enforce {
		t.Fatalf("older instruction applied: %v", err)
	}
	if err := set(context.Background(), "strict", 101); err == nil {
		t.Fatal("unknown mode accepted")
	}
	fi, err := os.Stat(filepath.Join(st.Dir(), "visitor", "7c9e6679-7425-40de-944b-e07fc1f90ae7", visitor.ModeFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode file: %v %v", fi, err)
	}
	if s, ok := h.visitorStatus().(visitor.ModeStatus); !ok || s.Mode != visitor.Enforce || s.Seq != 100 {
		t.Fatalf("status %#v", h.visitorStatus())
	}

	if visitorSeq(nil)() != math.MaxInt64 || visitorSeq(h.modeStore())() != 100 {
		t.Fatal("seq source")
	}

	h2 := newInstructions(nil, st, &trust{}, func(time.Time) bool { return false }, func(context.Context) error { return nil })
	if h2.visitorMode() != visitor.Enforce {
		t.Fatal("mode lost on restart")
	}
	other := "11111111-2222-4333-8444-555555555555"
	_ = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: other, FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000, APIURL: "https://api.seawise.io"}
		return nil
	})
	if h.visitorMode() != visitor.Observe {
		t.Fatal("another server inherited the mode")
	}
	_ = st.Update(func(s *store.State) error { s.Account = nil; return nil })
	if h.visitorMode() != visitor.Observe || h.modeStore() != nil {
		t.Fatal("unpaired server has a mode")
	}
	if err := setVisitorEnforcement(slog.New(slog.DiscardHandler), nil)(context.Background(), "enforce", 1); err == nil {
		t.Fatal("no store accepted")
	}

}
