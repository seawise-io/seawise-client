package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SEA-176: locks in the first-run wizard contract. When no password is set,
// only the setup endpoints are reachable; everything else returns 403. After
// a password is set, normal auth applies. Replaces the SEA-151 loopback-only
// hard refusal — the wizard endpoints are safe on a public bind because the
// only thing reachable is the password-setup form.
func TestMiddleware_FirstRunWizard_NoPassword(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())

	am := newAuthManager()
	t.Cleanup(am.Stop)

	if am.hasPassword() {
		t.Fatal("test precondition broken: fresh authManager should have no password")
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := am.middleware(next)

	// Setup-wizard endpoints MUST be reachable without authentication.
	reachable := []string{
		"/",
		"/static/app.js",
		"/static/style.css",
		"/api/status",
		"/api/auth/status",
		"/api/auth/login",
		"/api/auth/set-password",
	}
	for _, path := range reachable {
		t.Run("reachable_"+sanitizeTestName(path), func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			// Asserting == 200 (rather than != 403) catches the
			// quieter regression where a path becomes reachable but
			// the wrapped handler 500s on it.
			if rr.Code != http.StatusOK {
				t.Errorf("path %q should be reachable during first-run wizard with 200, got %d %q", path, rr.Code, rr.Body.String())
			}
		})
	}

	// Everything else MUST be blocked with 403 until a password is set —
	// prevents an attacker reaching the bind from claiming services or
	// the pairing flow before the operator finishes setup.
	blocked := []string{
		"/api/pair/start",
		"/api/pair/poll",
		"/api/services/list",
		"/api/services/add",
		"/api/unpair",
	}
	for _, path := range blocked {
		t.Run("blocked_"+sanitizeTestName(path), func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("path %q should be 403 during first-run wizard, got %d", path, rr.Code)
			}
			if !strings.Contains(rr.Body.String(), "Password setup required") {
				t.Errorf("path %q should return 'Password setup required' message, got %q", path, rr.Body.String())
			}
		})
	}
}

// Once a password is set the wizard is gone; protected endpoints require
// authentication. Locks in the transition out of first-run mode.
func TestMiddleware_AfterPasswordSet_RequiresSession(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())

	am := newAuthManager()
	t.Cleanup(am.Stop)

	if err := am.setPassword("hunter2-correct-horse"); err != nil {
		t.Fatalf("setPassword failed: %v", err)
	}
	if !am.hasPassword() {
		t.Fatal("password should be set after setPassword")
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	// API endpoints without a session cookie should return 401, not the
	// first-run 403 "setup required".
	req := httptest.NewRequest("GET", "/api/services/list", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("post-setup unauthenticated /api request should be 401, got %d body=%q", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Password setup required") {
		t.Errorf("post-setup response should not contain first-run message, got %q", rr.Body.String())
	}
}

// SEA-176: verifies the loopback bind classifier behaves correctly for the
// startup warning log path. Loopback addresses suppress the warning; everything
// else triggers it. (The function lives in server.go.)
func TestIsLoopbackBindAddr(t *testing.T) {
	cases := []struct {
		bind string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"127.0.0.2", true},
		{"::ffff:127.0.0.1", true},
		{"0.0.0.0", false},
		{"::", false},
		{"10.0.0.5", false},
		{"192.168.1.10", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.bind, func(t *testing.T) {
			if got := isLoopbackBindAddr(tc.bind); got != tc.want {
				t.Errorf("isLoopbackBindAddr(%q) = %v, want %v", tc.bind, got, tc.want)
			}
		})
	}
}

// SEA-176: hint URL in the first-run startup warning must produce a URL the
// operator can actually click — TLS scheme reflected, IPv6 bracketed, wildcard
// binds substituted with localhost.
func TestFirstRunHintURL(t *testing.T) {
	cases := []struct {
		bind string
		port int
		tls  string
		want string
	}{
		{"0.0.0.0", 8082, "", "http://127.0.0.1:8082/"},
		{"0.0.0.0", 8082, "auto", "https://127.0.0.1:8082/"},
		{"::", 8082, "", "http://[::1]:8082/"},
		{"127.0.0.1", 8082, "", "http://127.0.0.1:8082/"},
		{"10.0.0.5", 8082, "", "http://10.0.0.5:8082/"},
		{"fd00::1", 8082, "", "http://[fd00::1]:8082/"},
		{"fd00::1", 8082, "auto", "https://[fd00::1]:8082/"},
	}
	for _, tc := range cases {
		t.Run(tc.bind+"_"+tc.tls, func(t *testing.T) {
			t.Setenv("SEAWISE_TLS", tc.tls)
			if got := firstRunHintURL(tc.bind, tc.port); got != tc.want {
				t.Errorf("firstRunHintURL(%q, %d) [TLS=%q] = %q, want %q", tc.bind, tc.port, tc.tls, got, tc.want)
			}
		})
	}
}

func sanitizeTestName(s string) string {
	return strings.NewReplacer("/", "_", ".", "_", " ", "_").Replace(strings.TrimPrefix(s, "/"))
}
