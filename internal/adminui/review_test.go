package adminui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/seawise/client/internal/store"
)

type reviewHarness struct {
	t      *testing.T
	s      *Server
	st     *store.Store
	cookie *http.Cookie
	csrf   string
}

func newReviewHarness(t *testing.T, targets []store.Target) *reviewHarness {
	t.Helper()
	st := newStore(t, nil)
	if err := st.Update(func(s *store.State) error { s.Targets = targets; return nil }); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, st, &testClock{now: t0})
	s.cfg.Gateways = func() []netip.Addr { return nil }
	token, csrf := s.sess.create()
	return &reviewHarness{t: t, s: s, st: st, cookie: &http.Cookie{Name: SessionCookie, Value: token}, csrf: csrf}
}

func (h *reviewHarness) list() string {
	r := httptest.NewRequest("GET", "/api/targets/review", nil)
	r.Host = "localhost"
	r.AddCookie(h.cookie)
	w := httptest.NewRecorder()
	h.s.SecureHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		h.t.Fatalf("list %d", w.Code)
	}
	return w.Body.String()
}

func (h *reviewHarness) act(body string, withCSRF bool) int {
	r := httptest.NewRequest("POST", "/api/targets/review", strings.NewReader(body))
	r.Host = "localhost"
	r.Header.Set("Origin", "https://localhost")
	r.AddCookie(h.cookie)
	if withCSRF {
		r.Header.Set("X-CSRF-Token", h.csrf)
	}
	w := httptest.NewRecorder()
	h.s.SecureHandler().ServeHTTP(w, r)
	return w.Code
}

func (h *reviewHarness) target(id string) store.Target {
	for _, t := range h.st.State().Targets {
		if t.LocalID == id {
			return t
		}
	}
	h.t.Fatalf("no target %s", id)
	return store.Target{}
}

func TestReviewEndpoints(t *testing.T) {
	now := t0
	h := newReviewHarness(t, []store.Target{
		{LocalID: "a", Name: "site", Host: "203.0.114.5", Port: 443, Grandfathered: true, ConfirmedAt: &now, Source: store.SourceV1Machine},
		{LocalID: "b", Name: "meta", Host: "169.254.169.254", Port: 80, Grandfathered: true, ConfirmedAt: &now, Source: store.SourceV1Machine},
	})
	changed := 0
	h.s.cfg.OnTargetsChanged = func(context.Context) { changed++ }
	body := h.list()
	if !strings.Contains(body, `"local_id":"a"`) || !strings.Contains(body, `"required":["public"]`) ||
		!strings.Contains(body, `"refused":"cloud metadata address"`) || strings.Contains(body, "missing") {
		t.Fatalf("list %s", body)
	}
	if c := h.act(`{"local_id":"b","action":"disable"}`, false); c != 403 {
		t.Fatalf("no csrf %d", c)
	}
	// Nothing needs a confirmation: the action no longer exists.
	if c := h.act(`{"local_id":"a","action":"confirm"}`, true); c != http.StatusBadRequest || changed != 0 {
		t.Fatalf("confirm %d", c)
	}
	if c := h.act(`{"local_id":"b","action":"disable"}`, true); c != 200 || !h.target("b").Disabled || changed != 1 {
		t.Fatalf("disable %d", c)
	}
	if c := h.act(`{"local_id":"b","action":"enable"}`, true); c != 200 || h.target("b").Disabled {
		t.Fatalf("enable %d", c)
	}
	if c := h.act(`{"local_id":"zz","action":"disable"}`, true); c != 404 {
		t.Fatalf("unknown %d", c)
	}
	if c := h.act(`{"local_id":"a","action":"grant","grants":["smtp"]}`, true); c != 400 {
		t.Fatalf("extra fields %d", c)
	}
}

func TestServerDisableRequestActions(t *testing.T) {
	now := t0
	h := newReviewHarness(t, []store.Target{
		{LocalID: "a", Name: "one", Host: "192.168.1.20", Port: 80, ConfirmedAt: &now, Source: store.SourceLocal, ServerDisableRequestedAt: &now},
		{LocalID: "b", Name: "two", Host: "192.168.1.21", Port: 80, ConfirmedAt: &now, Source: store.SourceLocal, ServerDisableRequestedAt: &now},
	})
	if body := h.list(); !strings.Contains(body, `"server_disable_requested_at"`) {
		t.Fatalf("pending request not listed: %s", body)
	}
	if c := h.act(`{"local_id":"a","action":"accept_server_disable"}`, true); c != 200 {
		t.Fatalf("accept %d", c)
	}
	if a := h.target("a"); !a.Disabled || a.ServerDisableRequestedAt != nil {
		t.Fatalf("accept stored %+v", a)
	}
	if c := h.act(`{"local_id":"b","action":"dismiss_server_disable"}`, true); c != 200 {
		t.Fatalf("dismiss %d", c)
	}
	if b := h.target("b"); b.Disabled || b.ServerDisableRequestedAt != nil {
		t.Fatalf("dismiss stored %+v", b)
	}
	if c := h.act(`{"local_id":"b","action":"accept_server_disable"}`, true); c != http.StatusConflict {
		t.Fatalf("accept without request %d", c)
	}
}
