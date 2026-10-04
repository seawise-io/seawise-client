package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newSetupTestServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)
	return &Server{auth: am}
}

func postSetPassword(s *Server, body, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	s.handleAuthSetPassword(rr, req)
	return rr
}

func TestGenerateSetupCode(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		code, err := generateSetupCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 14 || code[4] != '-' || code[9] != '-' {
			t.Fatalf("unexpected format %q", code)
		}
		for _, r := range normalizeSetupCode(code) {
			if !strings.ContainsRune(setupCodeAlphabet, r) {
				t.Fatalf("code %q has char %q outside alphabet", code, r)
			}
		}
		seen[code] = true
	}
	if len(seen) < 50 {
		t.Errorf("setup codes repeated: %d unique of 50", len(seen))
	}
}

func TestSetPassword_RequiresSetupCode(t *testing.T) {
	s := newSetupTestServer(t)

	for _, body := range []string{
		`{"password":"hunter22hunter"}`,
		`{"password":"hunter22hunter","setup_code":"AAAA-BBBB-CCCC"}`,
	} {
		rr := postSetPassword(s, body, "203.0.113.7:5000")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("body %s: want 403, got %d %s", body, rr.Code, rr.Body.String())
		}
		s.auth.clearRateLimit("203.0.113.7")
	}
	if s.auth.hasPassword() {
		t.Fatal("password was set without a valid setup code")
	}
}

func TestSetPassword_AcceptsSetupCodeLoosely(t *testing.T) {
	s := newSetupTestServer(t)
	code := strings.ToLower(normalizeSetupCode(s.auth.setupCode))

	rr := postSetPassword(s, `{"password":"hunter22hunter","setup_code":"`+code+`"}`, "198.51.100.4:5000")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rr.Code, rr.Body.String())
	}
	if !s.auth.hasPassword() {
		t.Fatal("password not set")
	}
	if s.auth.checkSetupCode(code) {
		t.Fatal("setup code still valid after password was set")
	}
}

func TestSetPassword_WrongCodeIsRateLimited(t *testing.T) {
	s := newSetupTestServer(t)

	first := postSetPassword(s, `{"password":"hunter22hunter","setup_code":"WRONG"}`, "192.0.2.9:1111")
	if first.Code != http.StatusForbidden {
		t.Fatalf("first attempt: want 403, got %d", first.Code)
	}
	second := postSetPassword(s, `{"password":"hunter22hunter","setup_code":"`+s.auth.setupCode+`"}`, "192.0.2.9:2222")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("immediate retry: want 429, got %d", second.Code)
	}
}
