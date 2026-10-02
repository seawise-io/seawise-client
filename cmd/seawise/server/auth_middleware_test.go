package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seawise/client/internal/constants"
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
		"/healthz",
		"/readyz",
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

func TestOriginMatchesHost(t *testing.T) {
	cases := []struct {
		origin, host string
		want         bool
	}{
		{"http://127.0.0.1:8082", "127.0.0.1:8082", true},
		{"https://127.0.0.1:8082", "127.0.0.1:8082", true},
		{"http://10.0.0.5:8082", "10.0.0.5:8082", true},
		{"http://nas.example.com", "nas.example.com", true},
		{"https://[::1]:8082", "[::1]:8082", true},
		{"http://attacker.example", "10.0.0.5:8082", false},
		{"http://10.0.0.5:8082.attacker.example", "10.0.0.5:8082", false},
		{"null", "10.0.0.5:8082", false},
		{"", "10.0.0.5:8082", false},
		{"http://127.0.0.1:8082", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.origin+"/"+tc.host, func(t *testing.T) {
			if got := originMatchesHost(tc.origin, tc.host); got != tc.want {
				t.Errorf("originMatchesHost(%q, %q) = %v, want %v", tc.origin, tc.host, got, tc.want)
			}
		})
	}
}

func TestRefererMatchesHost(t *testing.T) {
	cases := []struct {
		referer, host string
		want          bool
	}{
		{"http://10.0.0.5:8082/", "10.0.0.5:8082", true},
		{"http://10.0.0.5:8082", "10.0.0.5:8082", true},
		{"https://10.0.0.5:8082/some/path?x=1", "10.0.0.5:8082", true},
		{"http://nas.example.com/login", "nas.example.com", true},
		{"http://10.0.0.5:8082.attacker.example/", "10.0.0.5:8082", false},
		{"http://10.0.0.5:8082attacker.example/", "10.0.0.5:8082", false},
		{"http://attacker.example/", "10.0.0.5:8082", false},
		{"", "10.0.0.5:8082", false},
		{"http://10.0.0.5:8082/", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.referer+"/"+tc.host, func(t *testing.T) {
			if got := refererMatchesHost(tc.referer, tc.host); got != tc.want {
				t.Errorf("refererMatchesHost(%q, %q) = %v, want %v", tc.referer, tc.host, got, tc.want)
			}
		})
	}
}

func TestMiddleware_CSRF_SameOriginAlwaysAccepted(t *testing.T) {
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

	cases := []struct {
		host, origin string
	}{
		{"127.0.0.1:8082", "http://127.0.0.1:8082"},
		{"10.0.0.5:8082", "http://10.0.0.5:8082"},
		{"192.168.1.10:8082", "http://192.168.1.10:8082"},
		{"nas.local:8082", "http://nas.local:8082"},
		{"[::1]:8082", "http://[::1]:8082"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/services/list", strings.NewReader(`{}`))
			req.Host = tc.host
			req.Header.Set("Origin", tc.origin)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "Cross-origin") {
				t.Errorf("same-origin POST from %q must not be CSRF-blocked, got %d %q", tc.host, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestMiddleware_CSRF_CrossOriginAlwaysBlocked(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	cases := []struct {
		name, host, originOrReferer, header string
	}{
		{"attacker-origin", "10.0.0.5:8082", "http://attacker.example", "Origin"},
		{"attacker-referer", "10.0.0.5:8082", "http://attacker.example/", "Referer"},
		{"suffix-bypass-origin", "10.0.0.5:8082", "http://10.0.0.5:8082.attacker.example", "Origin"},
		{"suffix-bypass-referer", "10.0.0.5:8082", "http://10.0.0.5:8082.attacker.example/", "Referer"},
		{"null-origin", "10.0.0.5:8082", "null", "Origin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
			req.Host = tc.host
			req.Header.Set(tc.header, tc.originOrReferer)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s: expected 403, got %d %q", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestMiddleware_CSRF_RejectsMissingOriginAndReferer(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
	req.Host = "10.0.0.5:8082"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("POST without Origin or Referer must be 403, got %d", rr.Code)
	}
}

func TestIsDevBuild(t *testing.T) {
	orig := constants.Version
	t.Cleanup(func() { constants.Version = orig })

	cases := map[string]bool{
		"dev":     true,
		"dev-abc": true,
		"v1.0.11": false,
		"1.2.3":   false,
		"":        false,
	}
	for v, want := range cases {
		constants.Version = v
		if got := isDevBuild(); got != want {
			t.Errorf("isDevBuild() with Version=%q = %v, want %v", v, got, want)
		}
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"debug", "DEBUG"},
		{"DEBUG", "DEBUG"},
		{"  Debug  ", "DEBUG"},
		{"info", "INFO"},
		{"", "INFO"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"trace", "INFO"},
	}
	for _, tc := range cases {
		if got := parseLogLevel(tc.in).String(); got != tc.want {
			t.Errorf("parseLogLevel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMiddleware_CSRF_RejectsDNSRebindingHost(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
	req.Host = "evil.example"
	req.Header.Set("Origin", "http://evil.example")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("DNS-name Host must be 403, got %d %q", rr.Code, rr.Body.String())
	}

	req2 := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
	req2.Host = "evil.example:8082"
	req2.Header.Set("Origin", "http://evil.example:8082")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("DNS-name Host with port must be 403, got %d %q", rr2.Code, rr2.Body.String())
	}
}

func TestIsHostAllowed(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:8082", true},
		{"127.0.0.1", true},
		{"[::1]:8082", true},
		{"::1", true},
		{"localhost:8082", true},
		{"localhost", true},
		{"192.168.2.86:8082", true},
		{"10.0.0.5:8082", true},
		{"[fe80::1]:8082", true},
		{"nas.local:8082", true},
		{"NAS.Local", true},
		{"evil.example", false},
		{"evil.example:8082", false},
		{"127.0.0.1.evil.example", false},
		{"evil.local.example", false},
		{"localhost.", true},
		{"127.0.0.1.", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := isHostAllowed(tc.host); got != tc.want {
			t.Errorf("isHostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// SEA-228 cloud escape hatch: SEAWISE_ALLOWED_HOSTS explicitly lists DNS
// names the operator wants to accept (EKS ingress, Cloud Run URL, ECS ALB,
// etc.). Case-insensitive, comma-separated, optional :port entries.
func TestIsHostAllowed_AllowedHostsEnv(t *testing.T) {
	t.Setenv("SEAWISE_ALLOWED_HOSTS", "client.mycompany.com, seawise-client.example.io:8443 ,LOUD.EXAMPLE")
	cases := []struct {
		host string
		want bool
	}{
		{"client.mycompany.com", true},
		{"client.mycompany.com:8082", true}, // port stripped before compare
		{"seawise-client.example.io", true}, // port on the env entry, request without
		{"seawise-client.example.io:8443", true},
		{"loud.example", true},            // case-insensitive match
		{"attacker.mycompany.com", false}, // subdomain not covered
		{"mycompany.com", false},          // parent domain not covered
		{"127.0.0.1", true},               // defaults still work
		{"nas.local", true},
	}
	for _, tc := range cases {
		if got := isHostAllowed(tc.host); got != tc.want {
			t.Errorf("isHostAllowed(%q) with SEAWISE_ALLOWED_HOSTS set = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// Empty env var must be identical to unset — no accidental "match anything"
// behaviour from a blank string.
func TestIsHostAllowed_EmptyAllowedHostsEnv(t *testing.T) {
	t.Setenv("SEAWISE_ALLOWED_HOSTS", "")
	if isHostAllowed("evil.example") {
		t.Error("empty SEAWISE_ALLOWED_HOSTS must not allow arbitrary DNS names")
	}
	if !isHostAllowed("127.0.0.1") {
		t.Error("empty SEAWISE_ALLOWED_HOSTS must not disable the default rules")
	}
}

// SEA-228 CSRF integration: with the env var set, a POST from that Origin
// against the same Host actually reaches the handler.
func TestMiddleware_CSRF_AllowedHostsEnvIntegration(t *testing.T) {
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	t.Setenv("SEAWISE_ALLOWED_HOSTS", "client.mycompany.com")
	am := newAuthManager()
	t.Cleanup(am.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := am.middleware(next)

	req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(`{}`))
	req.Host = "client.mycompany.com"
	req.Header.Set("Origin", "https://client.mycompany.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "Invalid host") {
		t.Errorf("SEAWISE_ALLOWED_HOSTS host must pass rebinding gate, got %d %q", rr.Code, rr.Body.String())
	}
}
