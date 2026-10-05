package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
)

type fakeAPI struct {
	list    []api.Service
	onBatch func(in []api.BatchServiceInput) []api.BatchRegisterResult
}

func newFakeAPIClient(t *testing.T, f *fakeAPI) *api.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/services"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": f.list})
		case r.Method == "POST" && r.URL.Path == "/api/services/register/batch" && f.onBatch != nil:
			var body struct {
				Services []api.BatchServiceInput `json:"services"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"services": f.onBatch(body.Services)}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := api.New(srv.URL)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	c.SetFRPToken(strings.Repeat("a", 64))
	return c
}

func mustLoadMachine(t *testing.T) *config.Machine {
	t.Helper()
	m, err := config.LoadMachine()
	if err != nil {
		t.Fatalf("load machine: %v", err)
	}
	return m
}

func mustSaveServices(t *testing.T, services []config.LocalService) {
	t.Helper()
	id, err := config.GenerateMachineID()
	if err != nil {
		t.Fatalf("generate machine id: %v", err)
	}
	if services == nil {
		services = []config.LocalService{}
	}
	m := &config.Machine{MachineID: id, Services: services}
	if err := m.Save(); err != nil {
		t.Fatalf("save machine: %v", err)
	}
}

func byName(m *config.Machine) map[string]config.LocalService {
	out := make(map[string]config.LocalService, len(m.Services))
	for _, s := range m.Services {
		out[s.Name] = s
	}
	return out
}

func TestReconcile_DisablesServiceDeletedOnServer(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-keep", Name: "keep", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-keep", Subdomain: "keep-sub"},
		{LocalID: "loc-drop", Name: "drop", Host: "127.0.0.1", Port: 81, ServerServiceID: "svr-drop", Subdomain: "drop-sub"},
	})
	c := newFakeAPIClient(t, &fakeAPI{list: []api.Service{{ID: "svr-keep", Name: "keep", Subdomain: "keep-sub"}}})

	changed, err := reconcileMachineServicesWithServer(t.Context(), c, "srv")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !changed {
		t.Error("expected changed=true")
	}

	got := byName(mustLoadMachine(t))
	if len(got) != 2 {
		t.Fatalf("local entry must be kept, not erased: %+v", got)
	}
	if got["keep"].Disabled || got["keep"].ServerServiceID != "svr-keep" {
		t.Errorf("keep changed: %+v", got["keep"])
	}
	drop := got["drop"]
	if !drop.Disabled || drop.ServerServiceID != "" || drop.Subdomain != "" || drop.Host != "127.0.0.1" || drop.Port != 81 {
		t.Errorf("drop should be disabled with local host/port intact: %+v", drop)
	}
}

func TestReconcile_NeverAddsServerOnlyServices(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-a", Subdomain: "a-sub"},
	})
	c := newFakeAPIClient(t, &fakeAPI{list: []api.Service{
		{ID: "svr-a", Name: "a", Subdomain: "a-sub"},
		{ID: "svr-evil", Name: "router", Host: "192.168.1.1", Port: 80, Subdomain: "evil-sub"},
	}})

	changed, err := reconcileMachineServicesWithServer(t.Context(), c, "srv")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if changed {
		t.Error("server-only service must not count as a change")
	}
	m := mustLoadMachine(t)
	if len(m.Services) != 1 || m.Services[0].Name != "a" {
		t.Fatalf("server-only service was written to machine.json: %+v", m.Services)
	}
}

func TestReconcile_LeavesUnregisteredLocalServicesAlone(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{{LocalID: "loc-new", Name: "new", Host: "127.0.0.1", Port: 80}})
	c := newFakeAPIClient(t, &fakeAPI{})

	if _, err := reconcileMachineServicesWithServer(t.Context(), c, "srv"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	m := mustLoadMachine(t)
	if len(m.Services) != 1 || m.Services[0].LocalID != "loc-new" || m.Services[0].Disabled {
		t.Errorf("unregistered local service changed: %+v", m.Services)
	}
}

func TestReconcile_APIErrorLeavesStateAlone(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-a", Subdomain: "a-sub"},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c, err := api.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.SetFRPToken(strings.Repeat("a", 64))

	if _, err := reconcileMachineServicesWithServer(t.Context(), c, "srv"); err == nil {
		t.Fatal("expected API error")
	}
	m := mustLoadMachine(t)
	if m.Services[0].Disabled || m.Services[0].ServerServiceID != "svr-a" {
		t.Errorf("state mutated on API failure: %+v", m.Services)
	}
}

func TestReconcile_NilAPIClientReturnsError(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	if _, err := reconcileMachineServicesWithServer(t.Context(), nil, "srv"); err == nil {
		t.Error("expected error for nil api client")
	}
}

func TestBuildTunnelServices_UsesOnlyLocalDefinitions(t *testing.T) {
	m := &config.Machine{Services: []config.LocalService{
		{Name: "nas", Host: "192.168.1.20", Port: 5000, ServerServiceID: "svr-nas", Subdomain: "nas-sub"},
		{Name: "off", Host: "127.0.0.1", Port: 1, ServerServiceID: "svr-off", Subdomain: "off-sub", Disabled: true},
		{Name: "pending", Host: "127.0.0.1", Port: 2},
		{Name: "gone", Host: "127.0.0.1", Port: 3, ServerServiceID: "svr-gone", Subdomain: "gone-sub"},
		{Name: "nosub", Host: "127.0.0.1", Port: 4, ServerServiceID: "svr-nosub"},
	}}
	apiList := []api.Service{
		{ID: "svr-nas", Name: "nas", Host: "10.9.9.9", Port: 22, Subdomain: "other-sub"},
		{ID: "svr-off", Subdomain: "off-sub"},
		{ID: "svr-nosub", Subdomain: "x"},
		{ID: "svr-evil", Name: "router", Host: "192.168.1.1", Port: 80, Subdomain: "evil-sub"},
	}

	got := buildTunnelServices(m, apiList)
	if len(got) != 1 {
		t.Fatalf("want only the nas tunnel, got %+v", got)
	}
	nas := got[0]
	if nas.LocalIP != "192.168.1.20" || nas.LocalPort != 5000 || nas.Subdomain != "nas-sub" || nas.Name != "nas" {
		t.Errorf("tunnel must use local host/port/subdomain, got %+v", nas)
	}
}

func TestRegisterLocalServices_MatchesOnRequestedName(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-plex", Name: " Plex ", Host: "127.0.0.1", Port: 32400},
		{LocalID: "loc-off", Name: "off", Host: "127.0.0.1", Port: 1, Disabled: true},
	})
	var sent []string
	c := newFakeAPIClient(t, &fakeAPI{onBatch: func(in []api.BatchServiceInput) []api.BatchRegisterResult {
		out := make([]api.BatchRegisterResult, 0, len(in))
		for _, s := range in {
			sent = append(sent, s.Name)
			out = append(out, api.BatchRegisterResult{ID: "svr-" + strings.TrimSpace(s.Name), Name: strings.TrimSpace(s.Name), RequestedName: s.Name, Subdomain: "sub-" + strings.TrimSpace(s.Name)})
		}
		return out
	}})

	if err := registerLocalServices(t.Context(), c, "srv"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(sent) != 1 || sent[0] != " Plex " {
		t.Fatalf("disabled services must not be registered; sent %q", sent)
	}
	got := byName(mustLoadMachine(t))
	if got[" Plex "].ServerServiceID != "svr-Plex" || got[" Plex "].Subdomain != "sub-Plex" {
		t.Errorf("registration not recorded: %+v", got[" Plex "])
	}
}

func TestRegisterLocalServices_LocalDeleteDuringRegisterWins(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80}})
	c := newFakeAPIClient(t, &fakeAPI{onBatch: func(in []api.BatchServiceInput) []api.BatchRegisterResult {
		if _, err := removeLocalServiceByLocalID("loc-a"); err != nil {
			t.Errorf("remove during register: %v", err)
		}
		return []api.BatchRegisterResult{{ID: "svr-a", Name: "a", RequestedName: "a", Subdomain: "a-sub"}}
	}})

	if err := registerLocalServices(t.Context(), c, "srv"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if m := mustLoadMachine(t); len(m.Services) != 0 {
		t.Fatalf("deleted service came back: %+v", m.Services)
	}
}

func TestReEnableThenRegister(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80, Disabled: true}})
	c := newFakeAPIClient(t, &fakeAPI{onBatch: func(in []api.BatchServiceInput) []api.BatchRegisterResult {
		return []api.BatchRegisterResult{{ID: "svr-a2", Name: "a", RequestedName: "a", Subdomain: "a2-sub"}}
	}})

	if svc, err := setLocalServiceDisabled("loc-a", false); err != nil || svc == nil || svc.Disabled {
		t.Fatalf("re-enable: svc=%+v err=%v", svc, err)
	}
	if err := registerLocalServices(t.Context(), c, "srv"); err != nil {
		t.Fatal(err)
	}
	a := mustLoadMachine(t).Services[0]
	if a.Disabled || a.ServerServiceID != "svr-a2" || a.Subdomain != "a2-sub" {
		t.Errorf("re-enabled service not registered: %+v", a)
	}
}

func TestClearServerRegistrations(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "a", Name: "a", Host: "h", Port: 1, ServerServiceID: "s1", Subdomain: "x"},
		{LocalID: "b", Name: "b", Host: "h", Port: 2, ServerServiceID: "s2", Subdomain: "y", Disabled: true},
	})
	if err := clearServerRegistrations(); err != nil {
		t.Fatal(err)
	}
	for _, s := range mustLoadMachine(t).Services {
		if s.ServerServiceID != "" || s.Subdomain != "" {
			t.Errorf("not cleared: %+v", s)
		}
	}
	if !byName(mustLoadMachine(t))["b"].Disabled {
		t.Error("clearing registrations must not re-enable a disabled service")
	}
}

func TestAddLocalService_ConcurrentWritersDontLoseUpdates(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, nil)

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := addLocalService(fmt.Sprintf("svc-%d", i), "127.0.0.1", 1000+i, ""); err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if n := len(mustLoadMachine(t).Services); n != 40 {
		t.Fatalf("lost updates: have %d of 40", n)
	}
}

func TestAddLocalService_DuplicateNameRejected(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{{LocalID: "a", Name: "Plex", Host: "h", Port: 1}})
	if _, err := addLocalService("plex", "h", 2, ""); err != ErrDuplicateServiceName {
		t.Fatalf("want ErrDuplicateServiceName, got %v", err)
	}
}
