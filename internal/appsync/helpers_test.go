package appsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/store"
)

const testServer = "11111111-2222-4333-8444-555555555555"

// fakeApp is one live app of the fake device API.
type fakeApp struct {
	ID        string
	LocalID   string // "" for an app registered through a v1 path
	Name      string
	Host      string
	Port      int
	Subdomain string
	Created   int
}

type stored struct {
	body   []byte
	status int
	answer []byte
}

// fault decides the answer of one call before the API runs it. It returns
// handled=false to let the call through; lost=true runs the call and then
// loses its answer (outcome unknown).
type fault func(r Request) (resp Response, err error, handled, lost bool)

// fakeAPI follows the device apps API contract.
type fakeAPI struct {
	mu         sync.Mutex
	apps       []*fakeApp
	tombstones []string
	dedupe     map[string]stored
	faults     []fault
	calls      []Request
	seq        int
	health     [][]byte
	// relayed marks answers as not authenticated, as stream 0 answers are.
	relayed bool
}

func (f *fakeAPI) Authenticated() bool { return !f.relayed }

func newFakeAPI() *fakeAPI { return &fakeAPI{dedupe: map[string]stored{}} }

func (f *fakeAPI) addV1App(name, host string, port int, sub string) *fakeApp {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	a := &fakeApp{ID: fmt.Sprintf("aaaaaaaa-0000-4000-8000-%012d", f.seq), Name: name, Host: host, Port: port, Subdomain: sub, Created: f.seq}
	f.apps = append(f.apps, a)
	return a
}

func (f *fakeAPI) push(fs ...fault) {
	f.mu.Lock()
	f.faults = append(f.faults, fs...)
	f.mu.Unlock()
}

func (f *fakeAPI) live() []fakeApp {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []fakeApp{}
	for _, a := range f.apps {
		out = append(out, *a)
	}
	return out
}

func (f *fakeAPI) byLocal(lid string) *fakeApp {
	for _, a := range f.apps {
		if a.LocalID == lid {
			return a
		}
	}
	return nil
}

func (f *fakeAPI) tombstoned(lid string) bool {
	for _, t := range f.tombstones {
		if t == lid {
			return true
		}
	}
	return false
}

func (f *fakeAPI) requests(m pb.DeviceMethod) []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Request
	for _, r := range f.calls {
		if r.Method == m {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAPI) Do(ctx context.Context, r Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	f.mu.Lock()
	r.Body = append([]byte(nil), r.Body...)
	f.calls = append(f.calls, r)
	var fl fault
	if len(f.faults) > 0 {
		fl, f.faults = f.faults[0], f.faults[1:]
	}
	f.mu.Unlock()
	lost := false
	if fl != nil {
		resp, err, handled, l := fl(r)
		if handled {
			return resp, err
		}
		lost = l
	}
	f.mu.Lock()
	resp := f.serve(r)
	f.mu.Unlock()
	if lost {
		return Response{}, errors.New("connection reset")
	}
	return resp, nil
}

func jsonResp(status int, v any) Response {
	b, _ := json.Marshal(v)
	return Response{Status: status, Body: b}
}

func (f *fakeAPI) serve(r Request) Response {
	switch r.Method {
	case pb.DeviceMethod_REGISTER_APPS, pb.DeviceMethod_DELETE_APPS:
		if !keyRe.MatchString(r.Key) {
			return jsonResp(400, map[string]string{"error": "invalid_request", "code": "idempotency_key"})
		}
		if s, ok := f.dedupe[r.Key]; ok {
			if !bytes.Equal(s.body, r.Body) {
				return jsonResp(409, map[string]string{"error": "idempotency_mismatch"})
			}
			return Response{Status: s.status, Body: s.answer}
		}
		var resp Response
		if r.Method == pb.DeviceMethod_REGISTER_APPS {
			resp = f.register(r.Body)
		} else {
			resp = f.del(r.Body)
		}
		if resp.Status == 200 {
			f.dedupe[r.Key] = stored{body: r.Body, status: 200, answer: resp.Body}
		}
		return resp
	case pb.DeviceMethod_LIST_APPS:
		return f.list()
	case pb.DeviceMethod_REPORT_HEALTH:
		f.health = append(f.health, r.Body)
		return jsonResp(200, map[string]int{"matched": 0, "changed": 0})
	}
	return jsonResp(404, map[string]string{"error": "not_found"})
}

func (f *fakeAPI) register(body []byte) Response {
	var in struct {
		Apps []RegisterItem `json:"apps"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Apps == nil || len(in.Apps) > MaxItems {
		return jsonResp(400, map[string]string{"error": "invalid_request", "code": "apps"})
	}
	type plan struct {
		app    *fakeApp
		create bool
		result string
	}
	plans := make([]plan, len(in.Apps))
	claimed := map[*fakeApp]bool{}
	for i, it := range in.Apps {
		if !ValidLocalID(it.LocalID) {
			return jsonResp(400, map[string]string{"error": "invalid_request", "code": "local_id"})
		}
		if f.tombstoned(it.LocalID) {
			plans[i] = plan{result: "deleted"}
			continue
		}
		a := f.byLocal(it.LocalID)
		if a == nil {
			for _, c := range f.apps {
				if c.LocalID == "" && c.Name == it.Name && !claimed[c] {
					a = c
					break
				}
			}
		}
		if a == nil {
			for _, c := range f.apps {
				if c.Name == it.Name {
					return jsonResp(409, map[string]any{"error": "name_taken", "index": i, "local_id": it.LocalID})
				}
			}
			plans[i] = plan{create: true, result: "created"}
			continue
		}
		for _, c := range f.apps {
			if c != a && c.Name == it.Name {
				return jsonResp(409, map[string]any{"error": "name_taken", "index": i, "local_id": it.LocalID})
			}
		}
		claimed[a] = true
		res := "unchanged"
		if a.LocalID != it.LocalID || a.Name != it.Name || a.Host != it.Host || a.Port != it.Port {
			res = "updated"
		}
		plans[i] = plan{app: a, result: res}
	}
	type item struct {
		LocalID   string  `json:"local_id"`
		ID        *string `json:"id"`
		Result    string  `json:"result"`
		Subdomain *string `json:"subdomain"`
	}
	out := []item{}
	for i, it := range in.Apps {
		p := plans[i]
		if p.result == "deleted" {
			out = append(out, item{LocalID: it.LocalID, Result: "deleted"})
			continue
		}
		a := p.app
		if p.create {
			f.seq++
			a = &fakeApp{ID: fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", f.seq), Subdomain: fmt.Sprintf("app-%d", f.seq), Created: f.seq}
			f.apps = append(f.apps, a)
		}
		a.LocalID, a.Name, a.Host, a.Port = it.LocalID, it.Name, it.Host, it.Port
		id, sub := a.ID, a.Subdomain
		out = append(out, item{LocalID: it.LocalID, ID: &id, Result: p.result, Subdomain: &sub})
	}
	return jsonResp(200, map[string]any{"items": out})
}

func (f *fakeAPI) del(body []byte) Response {
	var in struct {
		LocalIDs []string `json:"local_ids"`
	}
	if err := json.Unmarshal(body, &in); err != nil || len(in.LocalIDs) == 0 || len(in.LocalIDs) > MaxItems {
		return jsonResp(400, map[string]string{"error": "invalid_request", "code": "local_ids"})
	}
	type res struct {
		LocalID string  `json:"local_id"`
		ID      *string `json:"id"`
		Result  string  `json:"result"`
	}
	out := []res{}
	for _, lid := range in.LocalIDs {
		a := f.byLocal(lid)
		if a == nil {
			if !f.tombstoned(lid) {
				f.tombstones = append(f.tombstones, lid)
			}
			out = append(out, res{LocalID: lid, Result: "absent"})
			continue
		}
		f.removeApp(a)
		id := a.ID
		out = append(out, res{LocalID: lid, ID: &id, Result: "deleted"})
	}
	return jsonResp(200, map[string]any{"results": out})
}

func (f *fakeAPI) removeApp(a *fakeApp) {
	for i, c := range f.apps {
		if c == a {
			f.apps = append(f.apps[:i], f.apps[i+1:]...)
			break
		}
	}
	if a.LocalID != "" {
		f.tombstones = append(f.tombstones, a.LocalID)
	}
}

// ownerDelete deletes an app as the owner does on the website.
func (f *fakeAPI) ownerDelete(lid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := f.byLocal(lid); a != nil {
		f.removeApp(a)
	}
}

func (f *fakeAPI) list() Response {
	sort.SliceStable(f.apps, func(i, j int) bool { return f.apps[i].Created < f.apps[j].Created })
	apps := []map[string]any{}
	for _, a := range f.apps {
		var lid any
		if a.LocalID != "" {
			lid = a.LocalID
		}
		apps = append(apps, map[string]any{
			"id": a.ID, "local_id": lid, "name": a.Name, "subdomain": a.Subdomain, "host": a.Host, "port": a.Port,
			"status": "online", "icon_url": nil, "public_requested": false, "public_local": true, "created_at": "2026-10-31T00:00:00Z",
		})
	}
	del := append([]string{}, f.tombstones...)
	if len(del) > 200 {
		del = del[len(del)-200:]
	}
	return jsonResp(200, map[string]any{"apps": apps, "deleted": del})
}

// Faults.

func status(code int, body any) fault {
	return func(Request) (Response, error, bool, bool) { return jsonResp(code, body), nil, true, false }
}

func fail503() fault { return status(503, map[string]string{"error": "Service unavailable"}) }

func fail429(after time.Duration) fault {
	return func(Request) (Response, error, bool, bool) {
		r := jsonResp(429, map[string]string{"error": "rate_limited"})
		r.RetryAfter = after
		return r, nil, true, false
	}
}

func timeout() fault {
	return func(Request) (Response, error, bool, bool) { return Response{}, context.DeadlineExceeded, true, false }
}

func nonceChallenge() fault {
	return func(Request) (Response, error, bool, bool) {
		r := jsonResp(401, map[string]string{"error": "use_dpop_nonce", "code": "use_dpop_nonce"})
		r.NonceChallenge = true
		return r, nil, true, false
	}
}

func proofCode(code string) fault {
	return status(http.StatusUnauthorized, map[string]string{"error": "invalid_proof", "code": code})
}

// lostAnswer runs the call and loses its answer, as a crash or a dropped
// connection after the server committed.
func lostAnswer() fault {
	return func(Request) (Response, error, bool, bool) { return Response{}, nil, false, true }
}

// only applies f to calls of method m and lets others through.
func only(m pb.DeviceMethod, f fault) fault {
	return func(r Request) (Response, error, bool, bool) {
		if r.Method != m {
			return Response{}, nil, false, false
		}
		return f(r)
	}
}

// Test store and engine.

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newStore(t *testing.T, dir string, targets ...store.Target) *store.Store {
	t.Helper()
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "tok"; return nil }); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: testServer, APIURL: "https://api.example.test"}
		s.Import = &store.Import{Layout: "machine", ServerID: testServer, Files: []store.ImportedFile{}}
		s.Targets = append(s.Targets, targets...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func reopen(t *testing.T, st *store.Store, dir string) *store.Store {
	t.Helper()
	st.Close()
	n, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

type harness struct {
	t        *testing.T
	dir      string
	st       *store.Store
	api      *fakeAPI
	clk      *clock
	e        *Engine
	ident    []string
	identErr error
}

func newHarness(t *testing.T, targets ...store.Target) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, api: newFakeAPI(), clk: &clock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}}
	h.st = newStore(t, dir, targets...)
	h.start()
	return h
}

func (h *harness) start() {
	h.t.Helper()
	e, err := New(Config{
		Store: h.st, Carrier: h.api, Now: h.clk.Now, Rand: func(d time.Duration) time.Duration { return d },
		OnIdentity: func(_ context.Context, code string) error {
			h.ident = append(h.ident, code)
			return h.identErr
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.e = e
}

// restart simulates a process restart over the same data directory.
func (h *harness) restart() {
	h.t.Helper()
	h.st = reopen(h.t, h.st, h.dir)
	h.start()
}

// settle runs steps until the engine is idle, advancing the clock by each
// returned delay; it fails after max steps.
func (h *harness) settle(max int) {
	h.t.Helper()
	for i := 0; i < max; i++ {
		d := h.e.Step(context.Background())
		if h.e.idle() {
			return
		}
		h.clk.Add(d)
	}
	h.t.Fatalf("not idle after %d steps: %+v", max, h.e.Status())
}

func (h *harness) targets() []store.Target { return h.st.State().Targets }

func (h *harness) target(lid string) *store.Target {
	for _, t := range h.targets() {
		if t.LocalID == lid {
			return &t
		}
	}
	return nil
}

func app(name, host string, port int) store.Target {
	return store.Target{LocalID: NewLocalID(), Name: name, Host: host, Port: port, Source: store.SourceLocal}
}

func v1App(localHex, name, host string, port int, serverID, sub string) store.Target {
	return store.Target{LocalID: localHex, Name: name, Host: host, Port: port, ServerServiceID: serverID, Subdomain: sub, Source: store.SourceV1Machine, Grandfathered: true}
}
