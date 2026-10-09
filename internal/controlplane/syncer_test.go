package controlplane

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/store"
)

type fakeAgent struct {
	mu         sync.Mutex
	holds      map[string]bool
	reconciles int
}

func (a *fakeAgent) Hold(_ context.Context, r string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.holds == nil {
		a.holds = map[string]bool{}
	}
	a.holds[r] = true
	return nil
}

func (a *fakeAgent) Release(_ context.Context, r string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.holds, r)
	return nil
}

func (a *fakeAgent) Reconcile(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reconciles++
	return nil
}

func (a *fakeAgent) Status(context.Context) (agent.Status, error) {
	return agent.Status{Running: true, Proxies: []agent.ProxyStatus{{Name: "x", Status: "running"}}}, nil
}

func (a *fakeAgent) ConnectionID() string { return "conn-1" }

func (a *fakeAgent) held(r string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.holds[r]
}

func pairedStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = token; return nil }); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: serverID, FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000}
		s.Targets = []store.Target{
			{LocalID: "a", Name: "jellyfin", Host: "192.168.1.20", Port: 8096, ServerServiceID: sidA, Subdomain: "calm-otter", Source: store.SourceLocal},
			{LocalID: "b", Name: "plex", Host: "192.168.1.21", Port: 32400, ServerServiceID: sidB, Subdomain: "brave-seal", Source: store.SourceLocal},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newSyncer(t *testing.T, f *fakeServer, st *store.Store, ag *fakeAgent, clk *clock) *Syncer {
	t.Helper()
	s, err := NewSyncer(SyncerConfig{Client: f.client(t), Store: st, Agent: ag, Version: "test", Now: clk.Now, ListEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func stateBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, store.SubDir, store.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSyncerRemovalIsNeverDestructive(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		jsonReply(w, 410, `{"error":"Server not found","action":"unpair","reason":"server_deleted"}`)
	})
	st, dir := pairedStore(t)
	before := stateBytes(t, dir)
	ag := &fakeAgent{}
	clk := &clock{now: t0}
	s := newSyncer(t, f, st, ag, clk)
	ctx := context.Background()

	s.Step(ctx)
	if ag.held(agent.HoldRemoval) || !s.Status().Removal.Reported {
		t.Fatalf("single 410 acted on: %+v", s.Status())
	}
	clk.Add(5 * time.Minute)
	s.Step(ctx)
	clk.Add(5 * time.Minute)
	s.Step(ctx)
	if !ag.held(agent.HoldRemoval) || !s.Status().Removal.Confirmed {
		t.Fatalf("confirmed removal not held: %+v", s.Status())
	}
	if st.State().Account == nil || st.Secrets().FRPToken != token || len(st.State().Targets) != 2 {
		t.Fatal("removal deleted local state")
	}
	if string(stateBytes(t, dir)) != string(before) {
		t.Fatal("state file rewritten on removal")
	}
}

func TestSyncerSuccessReleasesRemovalHold(t *testing.T) {
	gone := true
	var mu sync.Mutex
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/api/servers/"+serverID+"/services" {
			jsonReply(w, 200, `{"data":[]}`)
			return
		}
		if gone {
			jsonReply(w, 410, `{"action":"unpair"}`)
			return
		}
		jsonReply(w, 200, okHeartbeat)
	})
	st, _ := pairedStore(t)
	ag := &fakeAgent{}
	clk := &clock{now: t0}
	s := newSyncer(t, f, st, ag, clk)
	for i := 0; i < 3; i++ {
		s.Step(context.Background())
		clk.Add(6 * time.Minute)
	}
	if !ag.held(agent.HoldRemoval) {
		t.Fatal("not held")
	}
	mu.Lock()
	gone = false
	mu.Unlock()
	s.Step(context.Background())
	if ag.held(agent.HoldRemoval) || s.Status().Removal.Reported {
		t.Fatalf("hold not released: %+v", s.Status())
	}
}

func TestSyncerEmptyListKeepsTargets(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == "GET" {
			jsonReply(w, 200, `{"data":[]}`)
			return
		}
		jsonReply(w, 200, okHeartbeat)
	})
	st, dir := pairedStore(t)
	before := stateBytes(t, dir)
	ag := &fakeAgent{}
	s := newSyncer(t, f, st, ag, &clock{now: t0})
	s.Step(context.Background())
	if string(stateBytes(t, dir)) != string(before) || ag.reconciles != 0 {
		t.Fatal("empty list changed state")
	}
	if got := kinds(Plan{Notices: s.Status().Notices}); got[NoticeEmptyList] != 1 {
		t.Fatalf("notices %+v", s.Status().Notices)
	}
}

func TestSyncerTransientKeepsState(t *testing.T) {
	for _, status := range []int{500, 503, 401, 403, 404, 302} {
		f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, status, `{"error":"x"}`) })
		st, dir := pairedStore(t)
		before := stateBytes(t, dir)
		ag := &fakeAgent{}
		s := newSyncer(t, f, st, ag, &clock{now: t0})
		d := s.Step(context.Background())
		if d <= 0 || d > 30*time.Second || ag.reconciles != 0 || len(ag.holds) != 0 || string(stateBytes(t, dir)) != string(before) {
			t.Fatalf("status %d acted on: delay %v %+v", status, d, ag)
		}
	}
}

func TestSyncerMigrateAppliesAllowedOnly(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == "GET" {
			jsonReply(w, 200, `{"data":[]}`)
			return
		}
		jsonReply(w, 200, `{"data":{"status":"migrate","migrate_to":{"frp_server_addr":"frp-2.seawise.dev","frp_server_port":7001}}}`)
	})
	st, _ := pairedStore(t)
	ag := &fakeAgent{}
	s := newSyncer(t, f, st, ag, &clock{now: t0})
	s.Step(context.Background())
	if a := st.State().Account; a.FRPServerAddr != "frp-2.seawise.dev" || a.FRPServerPort != 7001 || ag.reconciles != 1 {
		t.Fatalf("migrate: %+v %d", a, ag.reconciles)
	}
}

func TestSyncerSubdomainFill(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == "GET" {
			jsonReply(w, 200, `{"data":[{"id":"`+sidA+`","name":"jellyfin","host":"192.168.1.20","port":8096,"subdomain":"calm-otter","status":"online"}]}`)
			return
		}
		jsonReply(w, 200, okHeartbeat)
	})
	st, _ := pairedStore(t)
	_ = st.Update(func(s *store.State) error { s.Targets[0].Subdomain = ""; return nil })
	ag := &fakeAgent{}
	s := newSyncer(t, f, st, ag, &clock{now: t0})
	s.Step(context.Background())
	if got := st.State().Targets; got[0].Subdomain != "calm-otter" || got[1].Subdomain != "brave-seal" || ag.reconciles != 1 {
		t.Fatalf("targets %+v reconciles %d", got, ag.reconciles)
	}
}

func TestSyncerUnpairedDoesNothing(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) { jsonReply(w, 200, okHeartbeat) })
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := newSyncer(t, f, st, &fakeAgent{}, &clock{now: t0})
	s.Step(context.Background())
	if len(f.requests()) != 0 {
		t.Fatal("unpaired agent called the server")
	}
}

func TestSyncerServerDisableNeedsOwner(t *testing.T) {
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, n int) {
		if r.Method == "GET" {
			jsonReply(w, 200, `{"data":[{"id":"`+sidA+`","name":"jellyfin","host":"192.168.1.20","port":8096,"subdomain":"calm-otter","status":"disabled"}]}`)
			return
		}
		jsonReply(w, 200, okHeartbeat)
	})
	st, _ := pairedStore(t)
	ag := &fakeAgent{}
	clk := &clock{now: t0}
	s := newSyncer(t, f, st, ag, clk)
	s.Step(context.Background())
	clk.Add(11 * time.Minute)
	s.Step(context.Background())
	a := st.State().Targets[0]
	if a.Disabled || a.ServerDisableRequestedAt == nil || ag.reconciles != 0 || len(st.State().ServerDisableLog) != 1 {
		t.Fatalf("server disable not left to the owner: %+v reconciles %d", a, ag.reconciles)
	}
}
