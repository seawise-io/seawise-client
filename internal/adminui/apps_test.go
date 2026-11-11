package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/store"
)

const testServerID = "11111111-2222-4333-8444-555555555555"

// deviceAPI answers device calls with created apps and plain deletes.
type deviceAPI struct {
	mu    sync.Mutex
	seq   int
	calls []appsync.Request
}

func (d *deviceAPI) Authenticated() bool { return true }

func (d *deviceAPI) Do(_ context.Context, r appsync.Request) (appsync.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, r)
	switch r.Method {
	case pb.DeviceMethod_LIST_APPS:
		return appsync.Response{Status: 200, Body: []byte(`{"apps":[],"deleted":[]}`)}, nil
	case pb.DeviceMethod_REGISTER_APPS:
		var in struct {
			Apps []struct {
				LocalID string `json:"local_id"`
			} `json:"apps"`
		}
		_ = json.Unmarshal(r.Body, &in)
		items := []map[string]string{}
		for _, a := range in.Apps {
			d.seq++
			items = append(items, map[string]string{"local_id": a.LocalID, "id": fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", d.seq),
				"result": "created", "subdomain": fmt.Sprintf("app-%d", d.seq)})
		}
		b, _ := json.Marshal(map[string]any{"items": items})
		return appsync.Response{Status: 200, Body: b}, nil
	case pb.DeviceMethod_DELETE_APPS:
		var in struct {
			LocalIDs []string `json:"local_ids"`
		}
		_ = json.Unmarshal(r.Body, &in)
		res := []map[string]string{}
		for _, id := range in.LocalIDs {
			res = append(res, map[string]string{"local_id": id, "result": "deleted"})
		}
		b, _ := json.Marshal(map[string]any{"results": res})
		return appsync.Response{Status: 200, Body: b}, nil
	}
	return appsync.Response{Status: 404, Body: []byte(`{"error":"not_found"}`)}, nil
}

func (d *deviceAPI) requests(m pb.DeviceMethod) []appsync.Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []appsync.Request
	for _, r := range d.calls {
		if r.Method == m {
			out = append(out, r)
		}
	}
	return out
}

type appsHarness struct {
	*reviewHarness
	api     *deviceAPI
	e       *appsync.Engine
	changed int
}

func newAppsHarness(t *testing.T, targets ...store.Target) *appsHarness {
	t.Helper()
	h := &appsHarness{reviewHarness: newReviewHarness(t, targets), api: &deviceAPI{}}
	if err := h.st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "tok"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: testServerID, APIURL: "https://api.example.test"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := appsync.New(appsync.Config{Store: h.st, Carrier: h.api})
	if err != nil {
		t.Fatal(err)
	}
	h.e = e
	h.s.cfg.Apps = e
	h.s.cfg.OnTargetsChanged = func(context.Context) { h.changed++ }
	return h
}

func (h *appsHarness) settle() {
	h.t.Helper()
	for i := 0; i < 20; i++ {
		h.e.Step(context.Background())
		if s := h.e.Status(); s.OutboxDepth == 0 && s.Adopted && !s.LastSync.IsZero() {
			return
		}
	}
	h.t.Fatalf("not settled: %+v", h.e.Status())
}

func (h *appsHarness) byName(name string) *store.Target {
	for _, t := range h.st.State().Targets {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

func errorOf(t *testing.T, body string) string {
	t.Helper()
	var v struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("answer %q: %v", body, err)
	}
	return v.Error
}

func TestAppRoutesNeedSessionCSRFAndOrigin(t *testing.T) {
	h := newAppsHarness(t)
	add := `{"name":"Wiki","host":"192.168.1.21","port":8080}`
	cookie := h.cookie
	h.cookie = nil
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/apps", ""}, {"POST", "/api/apps/add", add}, {"POST", "/api/apps/delete", `{"local_id":"x"}`},
	} {
		if w := h.do(c.method, c.path, c.body, true); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without session: %d", c.method, c.path, w.Code)
		}
	}
	h.cookie = cookie
	for _, p := range []string{"/api/apps/add", "/api/apps/delete"} {
		if w := h.do("POST", p, add, false); w.Code != http.StatusForbidden {
			t.Fatalf("%s without CSRF: %d", p, w.Code)
		}
	}
	r := reqWithOrigin("POST", "/api/apps/add", add, "https://evil.example")
	r.AddCookie(h.cookie)
	r.Header.Set("X-CSRF-Token", h.csrf)
	if w := serve(h.s.SecureHandler(), r); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site add: %d", w.Code)
	}
	if w := h.do("GET", "/api/apps/add", "", false); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET add: %d", w.Code)
	}
	if len(h.st.State().Targets) != 0 {
		t.Fatalf("app added: %+v", h.st.State().Targets)
	}
}

func TestAddValidationMatchesV1(t *testing.T) {
	const (
		badName = "Invalid app name (must be 1-100 characters)"
		badHost = "Invalid host format (must be a valid hostname or IP)"
		blocked = "blocked: cloud metadata and link-local addresses cannot be exposed (security risk)"
		badPort = "Invalid port (must be 1-65535)"
		badBody = "Invalid request body"
	)
	h := newAppsHarness(t)
	for _, c := range []struct{ body, want string }{
		{`not json`, badBody},
		{`{"name":"a","host":"h","port":"80"}`, badBody},
		{`{"name":"a","host":"h","port":80,"icon_url":"x"}`, badBody},
		{`{"name":"a","host":"h","port":80} {}`, badBody},
		{`{"name":"","host":"h","port":80}`, badName},
		{`{"name":"   ","host":"h","port":80}`, badName},
		{`{"name":"` + strings.Repeat("a", 101) + `","host":"h","port":80}`, badName},
		{`{"name":"` + strings.Repeat("é", 51) + `","host":"h","port":80}`, badName},
		{`{"name":"a","host":"","port":80}`, badHost},
		{`{"name":"a","host":"h h","port":80}`, badHost},
		{`{"name":"a","host":"http://h","port":80}`, badHost},
		{`{"name":"a","host":"` + strings.Repeat("h", 256) + `","port":80}`, badHost},
		{`{"name":"a","host":"169.254.169.254","port":80}`, blocked},
		{`{"name":"a","host":"[fe80::1]","port":80}`, blocked},
		{`{"name":"a","host":"metadata.google.internal","port":80}`, blocked},
		{`{"name":"a","host":"h","port":0}`, badPort},
		{`{"name":"a","host":"h","port":65536}`, badPort},
		{`{"name":"a","host":"h"}`, badPort},
		{`{"name":"a\u0007b","host":"h","port":80}`, "name has control characters"},
	} {
		w := h.do("POST", "/api/apps/add", c.body, true)
		if w.Code != http.StatusBadRequest || errorOf(t, w.Body.String()) != c.want {
			t.Errorf("%s: %d %s, want %q", c.body, w.Code, w.Body, c.want)
		}
	}
	if n := len(h.st.State().Targets); n != 0 {
		t.Fatalf("%d apps stored from refused requests", n)
	}
	for _, c := range []struct {
		name, host string
		port       int
	}{{strings.Repeat("a", 100), "host.docker.internal", 1}, {" spaced ", "192.168.1.5", 65535}, {"v6", "[::1]", 8080}} {
		body, _ := json.Marshal(map[string]any{"name": c.name, "host": c.host, "port": c.port})
		if w := h.do("POST", "/api/apps/add", string(body), true); w.Code != 200 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
		if tg := h.byName(c.name); tg == nil || tg.Host != c.host || tg.Port != c.port || tg.Source != store.SourceLocal {
			t.Fatalf("stored %+v", tg)
		}
	}
}

func reqWithOrigin(method, path, body, origin string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "localhost"
	r.Header.Set("Origin", origin)
	return r
}

func TestAddDuplicateNameIsConflict(t *testing.T) {
	h := newAppsHarness(t)
	if w := h.do("POST", "/api/apps/add", `{"name":"Wiki","host":"10.0.0.1","port":80}`, true); w.Code != 200 {
		t.Fatalf("add %d", w.Code)
	}
	w := h.do("POST", "/api/apps/add", `{"name":"wIKI","host":"10.0.0.2","port":81}`, true)
	if w.Code != http.StatusConflict || errorOf(t, w.Body.String()) != "An app with that name already exists" {
		t.Fatalf("duplicate %d %s", w.Code, w.Body)
	}
}

func TestAddAndDeleteFlowThroughTheOutbox(t *testing.T) {
	h := newAppsHarness(t)
	h.settle()
	w := h.do("POST", "/api/apps/add", `{"name":"Wiki","host":"192.168.1.21","port":8080}`, true)
	if w.Code != 200 || h.changed != 1 {
		t.Fatalf("add %d %s changed %d", w.Code, w.Body, h.changed)
	}
	var added struct {
		OK  bool `json:"ok"`
		App struct {
			LocalID string `json:"local_id"`
			Status  string `json:"status"`
		} `json:"app"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil || !added.OK || !appsync.ValidLocalID(added.App.LocalID) || added.App.Status != "local-only" {
		t.Fatalf("answer %s", w.Body)
	}
	h.settle()
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) != 1 || !strings.Contains(string(regs[0].Body), added.App.LocalID) {
		t.Fatalf("register calls %+v", regs)
	}
	tg := h.byName("Wiki")
	if tg == nil || tg.ServerServiceID == "" || tg.Subdomain == "" {
		t.Fatalf("not registered: %+v", tg)
	}

	list := h.do("GET", "/api/apps", "", false)
	if list.Code != 200 || !strings.Contains(list.Body.String(), `"status":"registered"`) || !strings.Contains(list.Body.String(), `"subdomain":"`+tg.Subdomain+`"`) {
		t.Fatalf("list %d %s", list.Code, list.Body)
	}

	w = h.do("POST", "/api/apps/delete", `{"local_id":"`+tg.LocalID+`","service_name":"Wiki"}`, true)
	if w.Code != 200 || h.changed != 2 || h.byName("Wiki") != nil {
		t.Fatalf("delete %d %s changed %d", w.Code, w.Body, h.changed)
	}
	if s := h.e.Status(); s.OutboxDepth != 1 {
		t.Fatalf("delete not queued: %+v", s)
	}
	h.settle()
	dels := h.api.requests(pb.DeviceMethod_DELETE_APPS)
	if len(dels) != 1 || !strings.Contains(string(dels[0].Body), tg.LocalID) {
		t.Fatalf("delete calls %+v", dels)
	}
}

func TestDeleteByServiceIDAndErrors(t *testing.T) {
	h := newAppsHarness(t,
		store.Target{LocalID: "aaaaaaaa-0000-4000-8000-000000000001", Name: "One", Host: "10.0.0.1", Port: 80, ServerServiceID: "bbbbbbbb-0000-4000-8000-000000000001", Source: store.SourceLocal},
		store.Target{LocalID: "aaaaaaaa-0000-4000-8000-000000000002", Name: "Two", Host: "10.0.0.2", Port: 80, Source: store.SourceLocal})
	for _, c := range []struct {
		body string
		code int
		want string
	}{
		{`{}`, 400, "service_id or local_id is required"},
		{`{"service_name":"One"}`, 400, "service_id or local_id is required"},
		{`{"local_id":1}`, 400, "Invalid request body"},
		{`{"id":"x"}`, 400, "Invalid request body"},
		{`{"local_id":"aaaaaaaa-0000-4000-8000-000000000009"}`, 404, "App not found"},
		{`{"service_id":"bbbbbbbb-0000-4000-8000-000000000009"}`, 404, "App not found"},
	} {
		w := h.do("POST", "/api/apps/delete", c.body, true)
		if w.Code != c.code || errorOf(t, w.Body.String()) != c.want {
			t.Errorf("%s: %d %s", c.body, w.Code, w.Body)
		}
	}
	if w := h.do("POST", "/api/apps/delete", `{"service_id":"bbbbbbbb-0000-4000-8000-000000000001"}`, true); w.Code != 200 || h.byName("One") != nil {
		t.Fatalf("delete by service id %d %s", w.Code, w.Body)
	}
	if w := h.do("DELETE", "/api/apps/delete", `{"local_id":"aaaaaaaa-0000-4000-8000-000000000002"}`, true); w.Code != 200 || h.byName("Two") != nil {
		t.Fatalf("DELETE %d %s", w.Code, w.Body)
	}
}

func TestAppsListShape(t *testing.T) {
	h := newAppsHarness(t,
		store.Target{LocalID: "aaaaaaaa-0000-4000-8000-000000000001", Name: "<b>One</b>", Host: "10.0.0.1", Port: 80, ServerServiceID: "bbbbbbbb-0000-4000-8000-000000000001", Subdomain: "calm-otter", Source: store.SourceLocal},
		store.Target{LocalID: "aaaaaaaa-0000-4000-8000-000000000002", Name: "Two", Host: "10.0.0.2", Port: 81, Source: store.SourceLocal},
		store.Target{LocalID: "aaaaaaaa-0000-4000-8000-000000000003", Name: "Off", Host: "10.0.0.3", Port: 82, ServerServiceID: "bbbbbbbb-0000-4000-8000-000000000003", Disabled: true, Source: store.SourceLocal})
	w := h.do("GET", "/api/apps", "", false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<b>") {
		t.Fatalf("list %d %s", w.Code, w.Body)
	}
	var got struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Apps) != 3 {
		t.Fatalf("list %s", w.Body)
	}
	want := map[string]bool{"local_id": true, "name": true, "host": true, "port": true, "icon_url": true, "server_service_id": true, "subdomain": true, "status": true, "id": true}
	for _, a := range got.Apps {
		for k := range a {
			if !want[k] {
				t.Errorf("unexpected field %s", k)
			}
		}
	}
	for i, s := range []string{"registered", "local-only", "disabled"} {
		if got.Apps[i]["status"] != s {
			t.Errorf("app %d status %v, want %s", i, got.Apps[i]["status"], s)
		}
	}
	if got.Apps[0]["id"] != "bbbbbbbb-0000-4000-8000-000000000001" || got.Apps[0]["subdomain"] != "calm-otter" {
		t.Errorf("app 0 %+v", got.Apps[0])
	}
}

type fakeApps struct {
	kicks  int
	addErr error
	remErr error
}

func (f *fakeApps) Add(string, string, int) (string, error) {
	return "aaaaaaaa-0000-4000-8000-000000000001", f.addErr
}
func (f *fakeApps) Remove(string) error { return f.remErr }
func (f *fakeApps) Kick()               { f.kicks++ }

func TestReviewEnableWakesTheSync(t *testing.T) {
	now := t0
	h := newReviewHarness(t, []store.Target{
		{LocalID: "a", Name: "one", Host: "192.168.1.20", Port: 80, Disabled: true, Source: store.SourceLocal},
		{LocalID: "b", Name: "two", Host: "192.168.1.21", Port: 80, ServerDisableRequestedAt: &now, Source: store.SourceLocal},
	})
	f := &fakeApps{}
	h.s.cfg.Apps = f
	if c := h.act(`{"local_id":"a","action":"disable"}`, true); c != 200 || f.kicks != 0 {
		t.Fatalf("disable %d kicks %d", c, f.kicks)
	}
	if c := h.act(`{"local_id":"a","action":"enable"}`, true); c != 200 || f.kicks != 1 {
		t.Fatalf("enable %d kicks %d", c, f.kicks)
	}
	if c := h.act(`{"local_id":"b","action":"dismiss_server_disable"}`, true); c != 200 || f.kicks != 2 {
		t.Fatalf("dismiss %d kicks %d", c, f.kicks)
	}
	if c := h.act(`{"local_id":"zz","action":"enable"}`, true); c != 404 || f.kicks != 2 {
		t.Fatalf("unknown %d kicks %d", c, f.kicks)
	}
}

func TestAppErrorsMapped(t *testing.T) {
	h := newReviewHarness(t, []store.Target{{LocalID: "a", Name: "one", Host: "192.168.1.20", Port: 80, Source: store.SourceLocal}})
	add := `{"name":"x","host":"h","port":1}`
	del := `{"local_id":"a"}`
	if w := h.do("POST", "/api/apps/add", add, true); w.Code != http.StatusServiceUnavailable || errorOf(t, w.Body.String()) != "App sync is off on this client, so apps cannot be added here" {
		t.Fatalf("add without engine %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", "/api/apps/delete", del, true); w.Code != http.StatusServiceUnavailable || errorOf(t, w.Body.String()) != "App sync is off on this client, so apps cannot be deleted here" {
		t.Fatalf("delete without engine %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", "/api/apps", "", false); w.Code != 200 {
		t.Fatalf("list without engine %d", w.Code)
	}
	for _, c := range []struct {
		err  error
		code int
	}{
		{appsync.ErrTooManyApps, http.StatusConflict},
		{fmt.Errorf("%w: port must be 1-65535", appsync.ErrInvalidApp), http.StatusBadRequest},
		{errors.New("disk full"), http.StatusInternalServerError},
	} {
		h.s.cfg.Apps = &fakeApps{addErr: c.err}
		if w := h.do("POST", "/api/apps/add", add, true); w.Code != c.code || strings.Contains(w.Body.String(), "disk full") {
			t.Errorf("add %v: %d %s", c.err, w.Code, w.Body)
		}
	}
	for _, c := range []struct {
		err  error
		code int
	}{
		{appsync.ErrNoSuchApp, http.StatusNotFound},
		{appsync.ErrOutboxFull, http.StatusConflict},
		{errors.New("disk full"), http.StatusInternalServerError},
	} {
		h.s.cfg.Apps = &fakeApps{remErr: c.err}
		if w := h.do("POST", "/api/apps/delete", del, true); w.Code != c.code || strings.Contains(w.Body.String(), "disk full") {
			t.Errorf("delete %v: %d %s", c.err, w.Code, w.Body)
		}
	}
}

func TestUIAddsAndDeletesApps(t *testing.T) {
	html, _ := staticFS.ReadFile("static/index.html")
	for _, want := range []string{`id="apps"`, `id="add-app"`, `id="app-name"`, `id="app-host"`, `id="app-port"`, `maxlength="100"`, `min="1"`, `max="65535"`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("index.html has no %s", want)
		}
	}
	js, _ := staticFS.ReadFile("static/app.js")
	for _, want := range []string{`"/api/apps"`, `"/api/apps/add"`, `"/api/apps/delete"`, "This will stop exposing this app through Seawise.io."} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js does not use %s", want)
		}
	}
}

func TestAddAcceptsEveryTargetClassAsV1(t *testing.T) {
	h := newAppsHarness(t)
	i := 0
	for _, host := range []string{"127.0.0.1", "localhost", "192.168.1.1", "93.184.216.34", "host.docker.internal"} {
		for _, port := range []int{25, 2375, 2376, 2377, 2379, 2380, 6443, 10250, 10255} {
			i++
			body, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("app%d", i), "host": host, "port": port})
			if w := h.do("POST", "/api/apps/add", string(body), true); w.Code != 200 {
				t.Fatalf("%s: %d %s", body, w.Code, w.Body)
			}
		}
	}
	if n := len(h.st.State().Targets); n != i {
		t.Fatalf("stored %d of %d", n, i)
	}
}
