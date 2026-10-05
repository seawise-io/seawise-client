package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/connection"
	"github.com/seawise/client/internal/frp"
)

func newRecoveryTestServer(t *testing.T, savedAddr string, shard *api.ShardInfo) (*Server, *atomic.Int32) {
	t.Helper()
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())

	var heartbeats atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			heartbeats.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": api.HeartbeatResponse{Status: "ok", Shard: shard}})
		case strings.HasSuffix(r.URL.Path, "/services"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []api.Service{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	apiClient, err := api.New(srv.URL)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	token := strings.Repeat("a", 64)
	apiClient.SetFRPToken(token)

	cfg := &config.Config{
		ServerID:      "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
		FRPToken:      token,
		FRPServerAddr: savedAddr,
		FRPServerPort: 7000,
		FRPUseTLS:     true,
		APIURL:        srv.URL,
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Server{
		shutdownCtx:      ctx,
		cancel:           cancel,
		apiClient:        apiClient,
		cfg:              cfg,
		connManager:      connection.NewManager(connection.DefaultConfig()),
		serviceCache:     map[string]string{},
		lastHealthStatus: map[string]string{},
	}, &heartbeats
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func (s *Server) frpClientForTest() *frp.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.frpClient
}

func (s *Server) savedAddrForTest() (string, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.FRPServerAddr, s.cfg.FRPServerPort
}

func TestStartServices_DisallowedSavedAddrKeepsHeartbeat(t *testing.T) {
	s, heartbeats := newRecoveryTestServer(t, "203.0.113.10", nil)

	s.startServices(s.shutdownCtx)

	if s.frpClientForTest() != nil {
		t.Fatal("FRP client created for a disallowed saved address")
	}
	if got := s.connManager.State(); got != connection.StateDisconnected {
		t.Fatalf("state = %s, want %s", got, connection.StateDisconnected)
	}
	waitFor(t, func() bool { return heartbeats.Load() >= 1 })
}

func TestHeartbeat_BlockedClientAdoptsAllowedShard(t *testing.T) {
	s, heartbeats := newRecoveryTestServer(t, "203.0.113.10", &api.ShardInfo{FRPServerAddr: "frp-0.seawise.dev", FRPServerPort: 443})

	s.startServices(s.shutdownCtx)

	waitFor(t, func() bool { return s.frpClientForTest() != nil })
	time.Sleep(200 * time.Millisecond)
	if n := heartbeats.Load(); n != 1 {
		t.Fatalf("heartbeats = %d, want 1 (background loops started more than once)", n)
	}
	if addr, port := s.savedAddrForTest(); addr != "frp-0.seawise.dev" || port != 443 {
		t.Fatalf("saved addr = %s:%d, want frp-0.seawise.dev:443", addr, port)
	}
	persisted, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if persisted.FRPServerAddr != "frp-0.seawise.dev" || persisted.FRPServerPort != 443 {
		t.Fatalf("persisted addr = %s:%d, want frp-0.seawise.dev:443", persisted.FRPServerAddr, persisted.FRPServerPort)
	}
}

func TestHeartbeat_BlockedClientIgnoresUnusableShard(t *testing.T) {
	cases := map[string]*api.ShardInfo{
		"empty":     {FRPServerAddr: "", FRPServerPort: 0},
		"ip":        {FRPServerAddr: "198.51.100.7", FRPServerPort: 7000},
		"untrusted": {FRPServerAddr: "frp.example.com", FRPServerPort: 443},
	}
	for name, shard := range cases {
		t.Run(name, func(t *testing.T) {
			s, heartbeats := newRecoveryTestServer(t, "203.0.113.10", shard)

			s.startServices(s.shutdownCtx)
			waitFor(t, func() bool { return heartbeats.Load() >= 1 })
			time.Sleep(100 * time.Millisecond)

			if s.frpClientForTest() != nil {
				t.Fatal("FRP client created from an unusable shard address")
			}
			if addr, port := s.savedAddrForTest(); addr != "203.0.113.10" || port != 7000 {
				t.Fatalf("saved addr changed to %s:%d", addr, port)
			}
		})
	}
}

func TestAdoptFRPServerAddr_NoopWhileFRPRunning(t *testing.T) {
	s, _ := newRecoveryTestServer(t, "frp-1.seawise.dev", nil)
	s.frpClient = frp.New(frp.Config{ServerAddr: "frp-1.seawise.dev", ServerPort: 443})

	if s.adoptFRPServerAddr("frp-0.seawise.dev", 443) {
		t.Fatal("adopted a new address while FRP was running")
	}
	if addr, _ := s.savedAddrForTest(); addr != "frp-1.seawise.dev" {
		t.Fatalf("saved addr changed to %s", addr)
	}
}

func TestAdoptFRPServerAddr_NoopWhenUnpaired(t *testing.T) {
	s, _ := newRecoveryTestServer(t, "203.0.113.10", nil)
	s.cfg = nil

	if s.adoptFRPServerAddr("frp-0.seawise.dev", 443) {
		t.Fatal("adopted an address with no pairing config")
	}
}
