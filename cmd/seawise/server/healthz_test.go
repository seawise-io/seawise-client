package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seawise/client/internal/constants"
)

func TestHandleHealthz_AlwaysOKRegardlessOfState(t *testing.T) {
	cases := []struct {
		name  string
		state string
	}{
		{"fresh_install_unpaired", "none"},
		{"pairing_in_flight", "pending"},
		{"pair_approved_waiting", "approved"},
		{"fully_paired", "paired"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{pairingState: tc.state}

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			rr := httptest.NewRecorder()
			s.handleHealthz(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d body=%q", rr.Code, rr.Body.String())
			}

			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("body not valid JSON: %v (body=%q)", err, rr.Body.String())
			}
			if body["status"] != "ok" {
				t.Errorf("want status=ok, got %q", body["status"])
			}
			if body["version"] != constants.Version {
				t.Errorf("want version=%q, got %q", constants.Version, body["version"])
			}
			if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("want Content-Type application/json, got %q", ct)
			}
		})
	}
}

func TestHandleReadyz_FailureCombinations(t *testing.T) {
	cases := []struct {
		name           string
		pairingState   string
		wantPaired     bool
		wantFrpRunning bool
	}{
		{"unpaired_no_frp", "none", false, false},
		{"pending_no_frp", "pending", false, false},
		{"approved_no_frp", "approved", false, false},
		{"paired_but_no_frp_client", "paired", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{pairingState: tc.pairingState}

			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			rr := httptest.NewRecorder()
			s.handleReadyz(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("want 503, got %d body=%q", rr.Code, rr.Body.String())
			}

			var body map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("body not valid JSON: %v", err)
			}
			if body["status"] != "not_ready" {
				t.Errorf("want status=not_ready, got %v", body["status"])
			}
			if body["paired"] != tc.wantPaired {
				t.Errorf("want paired=%v, got %v", tc.wantPaired, body["paired"])
			}
			if body["frp_running"] != tc.wantFrpRunning {
				t.Errorf("want frp_running=%v, got %v", tc.wantFrpRunning, body["frp_running"])
			}
			if body["version"] != constants.Version {
				t.Errorf("want version in body, got %v", body["version"])
			}
		})
	}
}

func TestHealthEndpoints_ReachableWithoutSessionCookie(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())

	am := newAuthManager()
	t.Cleanup(am.Stop)

	s := &Server{pairingState: "none", auth: am}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	handler := am.middleware(mux)

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code == http.StatusForbidden {
				t.Fatalf("probe %q blocked by auth middleware — CSRF allow-list regression", path)
			}
			if rr.Code != http.StatusOK && rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("unexpected status %d on %q", rr.Code, path)
			}
		})
	}
}
