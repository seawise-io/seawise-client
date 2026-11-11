package adminui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestDisconnectNeedsSessionCSRFAndOrigin(t *testing.T) {
	h := newReviewHarness(t, nil)
	calls := 0
	h.s.cfg.Disconnect = func(context.Context) (Disconnected, error) { calls++; return Disconnected{Told: true}, nil }
	cookie := h.cookie
	h.cookie = nil
	if w := h.do("POST", "/api/disconnect", "", true); w.Code != http.StatusUnauthorized {
		t.Fatalf("without session: %d", w.Code)
	}
	h.cookie = cookie
	if w := h.do("POST", "/api/disconnect", "", false); w.Code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	r := reqWithOrigin("POST", "/api/disconnect", "", "https://evil.example")
	r.AddCookie(h.cookie)
	r.Header.Set("X-CSRF-Token", h.csrf)
	if w := serve(h.s.SecureHandler(), r); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", w.Code)
	}
	if w := h.do("GET", "/api/disconnect", "", true); w.Code == http.StatusOK {
		t.Fatal("GET disconnected")
	}
	if calls != 0 {
		t.Fatalf("disconnected %d times without a valid request", calls)
	}
	w := h.do("POST", "/api/disconnect", "", true)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"told":true}` || calls != 1 {
		t.Fatalf("disconnect: %d %s (%d calls)", w.Code, w.Body, calls)
	}
}

func TestDisconnectAnswers(t *testing.T) {
	h := newReviewHarness(t, nil)
	if w := h.do("POST", "/api/disconnect", "", true); w.Code != http.StatusServiceUnavailable || errorOf(t, w.Body.String()) == "" {
		t.Fatalf("off: %d %s", w.Code, w.Body)
	}
	for _, c := range []struct {
		d    Disconnected
		err  error
		code int
		body string
	}{
		{Disconnected{Told: false}, nil, http.StatusOK, `{"told":false}`},
		{Disconnected{}, ErrNotPaired, http.StatusConflict, "This client is not paired"},
		{Disconnected{}, errors.New("disk full"), http.StatusInternalServerError, "Could not disconnect this client"},
	} {
		h.s.cfg.Disconnect = func(context.Context) (Disconnected, error) { return c.d, c.err }
		w := h.do("POST", "/api/disconnect", "", true)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.body) || strings.Contains(w.Body.String(), "disk full") {
			t.Errorf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
}
