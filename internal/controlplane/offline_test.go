package controlplane

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

// runUntilBeats runs the syncer until the server saw beats heartbeats, then
// stops it and returns how long Run took to return after the stop.
func runUntilBeats(t *testing.T, s *Syncer, beats *atomic.Int32, n int32) time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for beats.Load() < n {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("only %d heartbeats", beats.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after stop")
	}
	return time.Since(start)
}

func offlineSyncer(t *testing.T, f *fakeServer, st *store.Store, legacy func() bool) *Syncer {
	t.Helper()
	after := func(d time.Duration) <-chan time.Time {
		c := make(chan time.Time, 1)
		c <- time.Time{}
		return c
	}
	s, err := NewSyncer(SyncerConfig{Client: f.client(t), Store: st, Agent: &fakeAgent{}, Version: "test", Now: (&clock{now: t0}).Now,
		After: after, Legacy: legacy, OfflineTimeout: 300 * time.Millisecond, SkipList: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func countOffline(f *fakeServer) (n int, tok string) {
	for _, r := range f.requests() {
		if r.Method == http.MethodPost && r.Path == "/api/servers/"+serverID+"/offline" {
			n++
			tok = r.Header.Get("X-FRP-Token")
		}
	}
	return n, tok
}

func TestSyncerSendsOfflineOnStop(t *testing.T) {
	var beats atomic.Int32
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Path == "/api/servers/"+serverID+"/heartbeat" {
			beats.Add(1)
		}
		jsonReply(w, 200, okHeartbeat)
	})
	st, _ := pairedStore(t)
	runUntilBeats(t, offlineSyncer(t, f, st, nil), &beats, 1)
	n, tok := countOffline(f)
	if n != 1 || tok != token {
		t.Fatalf("offline calls %d with the token %v, want 1", n, tok == token)
	}
	reqs := f.requests()
	if last := reqs[len(reqs)-1]; last.Path != "/api/servers/"+serverID+"/offline" {
		t.Fatalf("last call %s %s, want offline", last.Method, last.Path)
	}
}

func TestSyncerNoOfflineWithoutAGoodHeartbeat(t *testing.T) {
	var beats atomic.Int32
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		beats.Add(1)
		jsonReply(w, 503, `{"error":"unavailable"}`)
	})
	st, _ := pairedStore(t)
	runUntilBeats(t, offlineSyncer(t, f, st, nil), &beats, 2)
	if n, _ := countOffline(f); n != 0 {
		t.Fatalf("offline sent %d times without a good heartbeat", n)
	}
}

func TestSyncerNoOfflineAfterEnrolment(t *testing.T) {
	var beats atomic.Int32
	var legacy atomic.Bool
	legacy.Store(true)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		beats.Add(1)
		legacy.Store(false)
		jsonReply(w, 200, okHeartbeat)
	})
	st, _ := pairedStore(t)
	runUntilBeats(t, offlineSyncer(t, f, st, legacy.Load), &beats, 1)
	if n, _ := countOffline(f); n != 0 {
		t.Fatal("offline sent with the 1.x token after enrolment")
	}
}

func TestSyncerNoOfflineWithoutToken(t *testing.T) {
	var beats atomic.Int32
	st, _ := pairedStore(t)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		// The token is cleared once the switch is confirmed; the store
		// allows an account without one only then.
		if err := st.Update(func(s *store.State) error {
			s.Enrolment = &store.Enrolment{ServerID: serverID, Phase: store.PhaseSwitched, KeyID: "k", StartedAt: t0}
			return nil
		}); err != nil {
			t.Error(err)
		}
		if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = ""; return nil }); err != nil {
			t.Error(err)
		}
		beats.Add(1)
		jsonReply(w, 200, okHeartbeat)
	})
	runUntilBeats(t, offlineSyncer(t, f, st, nil), &beats, 1)
	if n, _ := countOffline(f); n != 0 {
		t.Fatal("offline sent without a token")
	}
}

// Another install took the server over: going offline would mark the live
// one offline.
func TestSyncerNoOfflineWhenSuperseded(t *testing.T) {
	var beats atomic.Int32
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if beats.Add(1) == 1 {
			jsonReply(w, 200, okHeartbeat)
			return
		}
		jsonReply(w, 409, `{"error":"Connection superseded","action":"superseded"}`)
	})
	st, _ := pairedStore(t)
	runUntilBeats(t, offlineSyncer(t, f, st, nil), &beats, 2)
	if n, _ := countOffline(f); n != 0 {
		t.Fatal("offline sent after the server was superseded")
	}
}

func TestSyncerNoOfflineAfterRemoval(t *testing.T) {
	var beats atomic.Int32
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if beats.Add(1) == 1 {
			jsonReply(w, 200, okHeartbeat)
			return
		}
		jsonReply(w, 410, `{"error":"Server not found","action":"unpair","reason":"deleted"}`)
	})
	st, _ := pairedStore(t)
	runUntilBeats(t, offlineSyncer(t, f, st, nil), &beats, 2)
	if n, _ := countOffline(f); n != 0 {
		t.Fatal("offline sent after the server reported removal")
	}
}

func TestSyncerOfflineIsBounded(t *testing.T) {
	var beats atomic.Int32
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.URL.Path == "/api/servers/"+serverID+"/offline" {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		beats.Add(1)
		jsonReply(w, 200, okHeartbeat)
	})
	st, _ := pairedStore(t)
	if took := runUntilBeats(t, offlineSyncer(t, f, st, nil), &beats, 1); took > 2*time.Second {
		t.Fatalf("stop took %v with a hanging offline call", took)
	}
	if n, _ := countOffline(f); n != 1 {
		t.Fatalf("offline attempted %d times, want exactly 1", n)
	}
}

// The default leaves room inside Docker's 10 s stop grace period.
func TestSyncerOfflineTimeoutDefault(t *testing.T) {
	st, _ := pairedStore(t)
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 200, okHeartbeat) })
	for _, in := range []time.Duration{0, -time.Second} {
		s, err := NewSyncer(SyncerConfig{Client: f.client(t), Store: st, Agent: &fakeAgent{}, OfflineTimeout: in})
		if err != nil {
			t.Fatal(err)
		}
		if s.cfg.OfflineTimeout != 5*time.Second {
			t.Fatalf("offline timeout %v for %v, want 5s", s.cfg.OfflineTimeout, in)
		}
	}
}
