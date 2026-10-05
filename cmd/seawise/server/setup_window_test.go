package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newSetupTestServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("SEAWISE_DATA_DIR", t.TempDir())
	am := newAuthManager()
	t.Cleanup(am.Stop)
	return &Server{auth: am}
}

func postSetPassword(s *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/auth/set-password", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleAuthSetPassword(rr, req)
	return rr
}

func TestSetPassword_WithinSetupWindow(t *testing.T) {
	s := newSetupTestServer(t)
	if s.auth.setupTimedOut() {
		t.Fatal("fresh client reports setup timed out")
	}

	rr := postSetPassword(s, `{"password":"hunter22hunter"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rr.Code, rr.Body.String())
	}
	if !s.auth.hasPassword() {
		t.Fatal("password not set")
	}
}

func TestSetPassword_AfterSetupWindow(t *testing.T) {
	s := newSetupTestServer(t)
	s.auth.mu.Lock()
	s.auth.setupDeadline = time.Now().Add(-time.Second)
	s.auth.mu.Unlock()

	if !s.auth.setupTimedOut() {
		t.Fatal("expected setup to be timed out")
	}
	rr := postSetPassword(s, `{"password":"hunter22hunter"}`)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "timed out") {
		t.Fatalf("want 403 timed out, got %d %s", rr.Code, rr.Body.String())
	}
	if s.auth.hasPassword() {
		t.Fatal("password set after setup window closed")
	}
}

func TestSetupTimedOut_FalseOncePasswordSet(t *testing.T) {
	s := newSetupTestServer(t)
	if err := s.auth.setPassword("hunter22hunter"); err != nil {
		t.Fatal(err)
	}
	s.auth.mu.Lock()
	s.auth.setupDeadline = time.Now().Add(-time.Hour)
	s.auth.mu.Unlock()

	if s.auth.setupTimedOut() {
		t.Fatal("setupTimedOut true for a client that already has a password")
	}
}
