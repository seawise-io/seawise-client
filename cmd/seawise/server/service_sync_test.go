package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
)

func newAPIClientForTest(t *testing.T, listResponse []api.Service) (*api.Client, *int) {
	t.Helper()
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/services") && r.Method == "GET" {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{"data": listResponse}); err != nil {
				t.Errorf("encode list response: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest url: %v", err)
	}
	// api.New requires HTTPS for non-loopback. httptest uses 127.0.0.1 so it passes.
	if u.Hostname() == "" {
		t.Fatalf("unexpected httptest URL %q", srv.URL)
	}

	c, err := api.New(srv.URL)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	c.SetFRPToken(strings.Repeat("a", 64))
	return c, &callCount
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

func TestReconcile_PrunesServiceDeletedOnServer(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-keep", Name: "keep", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-keep", Subdomain: "keep-sub"},
		{LocalID: "loc-drop", Name: "drop", Host: "127.0.0.1", Port: 81, ServerServiceID: "svr-drop", Subdomain: "drop-sub"},
	})
	apiClient, _ := newAPIClientForTest(t, []api.Service{
		{ID: "svr-keep", Name: "keep", Host: "127.0.0.1", Port: 80, Subdomain: "keep-sub"},
	})

	if err := reconcileMachineServicesWithServer(t.Context(), apiClient, nil, "any-server-id"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	m := mustLoadMachine(t)
	if len(m.Services) != 1 {
		t.Fatalf("expected 1 service after prune, got %d: %+v", len(m.Services), m.Services)
	}
	if m.Services[0].ServerServiceID != "svr-keep" {
		t.Errorf("wrong service kept: %+v", m.Services[0])
	}
}

func TestReconcile_LeavesUnregisteredLocalServicesAlone(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-new", Name: "new", Host: "127.0.0.1", Port: 80}, // ServerServiceID = ""
	})
	apiClient, _ := newAPIClientForTest(t, []api.Service{})

	if err := reconcileMachineServicesWithServer(t.Context(), apiClient, nil, "any-server-id"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	m := mustLoadMachine(t)
	if len(m.Services) != 1 || m.Services[0].LocalID != "loc-new" {
		t.Errorf("unregistered local-only service should be preserved, got %+v", m.Services)
	}
}

func TestReconcile_AddsServerServicesMissingLocally(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{})
	apiClient, _ := newAPIClientForTest(t, []api.Service{
		{ID: "svr-new", Name: "from-web", Host: "10.0.0.5", Port: 9000, Subdomain: "from-web-sub"},
	})

	if err := reconcileMachineServicesWithServer(t.Context(), apiClient, nil, "any-server-id"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	m := mustLoadMachine(t)
	if len(m.Services) != 1 {
		t.Fatalf("expected 1 service added, got %d", len(m.Services))
	}
	got := m.Services[0]
	if got.ServerServiceID != "svr-new" || got.Name != "from-web" || got.Host != "10.0.0.5" || got.Port != 9000 || got.Subdomain != "from-web-sub" {
		t.Errorf("re-hydrated entry mismatch: %+v", got)
	}
	if got.LocalID == "" {
		t.Errorf("re-hydrated entry must have a generated LocalID")
	}
}

func TestReconcile_NoChangeMeansNoSave(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	original := []config.LocalService{
		{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-a", Subdomain: "a-sub"},
	}
	mustSaveServices(t, original)
	apiClient, _ := newAPIClientForTest(t, []api.Service{
		{ID: "svr-a", Name: "a", Host: "127.0.0.1", Port: 80, Subdomain: "a-sub"},
	})

	if err := reconcileMachineServicesWithServer(t.Context(), apiClient, nil, "any-server-id"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	m := mustLoadMachine(t)
	if len(m.Services) != 1 || m.Services[0].LocalID != "loc-a" {
		t.Errorf("steady-state reconcile must not mutate machine state: %+v", m.Services)
	}
}

func TestReconcile_APIErrorIsNonFatal(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-a"},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, err := api.New(srv.URL)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	c.SetFRPToken(strings.Repeat("a", 64))

	err = reconcileMachineServicesWithServer(t.Context(), c, nil, "any-server-id")
	if err == nil {
		t.Fatalf("expected API error to propagate, got nil")
	}

	m := mustLoadMachine(t)
	if len(m.Services) != 1 {
		t.Errorf("machine state must not be mutated on API failure, got %d services", len(m.Services))
	}
}

func TestReconcile_HandlesMixedPruneAndAdd(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	mustSaveServices(t, []config.LocalService{
		{LocalID: "loc-a", Name: "a", Host: "127.0.0.1", Port: 80, ServerServiceID: "svr-a"},
		{LocalID: "loc-b", Name: "b", Host: "127.0.0.1", Port: 81, ServerServiceID: "svr-b"},
		{LocalID: "loc-pending", Name: "pending", Host: "127.0.0.1", Port: 82},
	})
	apiClient, _ := newAPIClientForTest(t, []api.Service{
		{ID: "svr-a", Name: "a", Host: "127.0.0.1", Port: 80, Subdomain: "a-sub"},
		{ID: "svr-c", Name: "c-from-web", Host: "127.0.0.1", Port: 83, Subdomain: "c-sub"},
	})

	if err := reconcileMachineServicesWithServer(t.Context(), apiClient, nil, "any-server-id"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	m := mustLoadMachine(t)
	names := make(map[string]config.LocalService, len(m.Services))
	for _, s := range m.Services {
		names[s.Name] = s
	}
	if len(names) != 3 {
		t.Fatalf("expected 3 services (a kept, pending kept, c added), got %d: %+v", len(names), m.Services)
	}
	if _, ok := names["a"]; !ok {
		t.Errorf("service 'a' must be kept")
	}
	if _, ok := names["b"]; ok {
		t.Errorf("service 'b' must be pruned (server no longer has svr-b)")
	}
	if _, ok := names["pending"]; !ok {
		t.Errorf("unregistered 'pending' must be kept")
	}
	c, ok := names["c-from-web"]
	if !ok {
		t.Errorf("service 'c-from-web' must be added")
	} else if c.ServerServiceID != "svr-c" {
		t.Errorf("added entry has wrong server id: %+v", c)
	}
}

func TestReconcile_NilAPIClientReturnsError(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	if err := reconcileMachineServicesWithServer(t.Context(), nil, nil, "any-server-id"); err == nil {
		t.Errorf("expected error for nil api client, got nil")
	}
}

// silence unused import warnings if any test is removed
var _ = fmt.Sprintf
