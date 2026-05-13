package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
			// `== 200` not `!= 403` so a 500 regression also fails.
			if rr.Code != http.StatusOK {
				t.Errorf("path %q should be reachable during first-run wizard with 200, got %d %q", path, rr.Code, rr.Body.String())
			}
		})
	}

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

func TestMiddleware_CSRF_AcceptsSameOriginDuringFirstRun(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	cases := []struct {
		host, origin string
	}{
		{"10.0.0.5:8082", "http://10.0.0.5:8082"},
		{"192.168.1.10:8082", "http://192.168.1.10:8082"},
		{"my-nas.local:8082", "http://my-nas.local:8082"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
			req.Host = tc.host
			req.Header.Set("Origin", tc.origin)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code == http.StatusForbidden {
				t.Errorf("first-run same-origin POST from %q should not be CSRF-blocked, got 403: %q", tc.host, rr.Body.String())
			}
		})
	}
}

func TestMiddleware_CSRF_StrictAfterPasswordSet(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)
	if err := am.setPassword("hunter2-correct-horse"); err != nil {
		t.Fatalf("setPassword: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
	req.Host = "10.0.0.5:8082"
	req.Header.Set("Origin", "http://10.0.0.5:8082")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("post-setup non-loopback same-origin POST should be CSRF-blocked, got %d", rr.Code)
	}
}
