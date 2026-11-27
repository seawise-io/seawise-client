package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/seawise/client/internal/pair"
)

type fakePairing struct {
	err     error
	started []string
	cancels int
	status  pair.Status
}

func (f *fakePairing) Start(_ context.Context, name string) (pair.Status, error) {
	f.started = append(f.started, name)
	if f.err != nil {
		return pair.Status{}, f.err
	}
	f.status = pair.Status{State: pair.StatePending, Code: "ABCDEFGHJK"}
	return f.status, nil
}

func (f *fakePairing) Cancel() {
	f.cancels++
	f.status = pair.Status{State: pair.StateIdle}
}

func (f *fakePairing) Status() pair.Status { return f.status }

func TestPairRoutesNeedSessionCSRFAndOrigin(t *testing.T) {
	h := newReviewHarness(t, nil)
	f := &fakePairing{status: pair.Status{State: pair.StateIdle}}
	h.s.cfg.Pairing = f
	cookie := h.cookie
	h.cookie = nil
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/pair/status", ""}, {"POST", "/api/pair/start", `{"server_name":"nas"}`}, {"POST", "/api/pair/cancel", ""},
	} {
		if w := h.do(c.method, c.path, c.body, true); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without session: %d", c.method, c.path, w.Code)
		}
	}
	h.cookie = cookie
	for _, p := range []string{"/api/pair/start", "/api/pair/cancel"} {
		if w := h.do("POST", p, `{}`, false); w.Code != http.StatusForbidden {
			t.Fatalf("%s without CSRF: %d", p, w.Code)
		}
	}
	r := reqWithOrigin("POST", "/api/pair/start", `{"server_name":"nas"}`, "https://evil.example")
	r.AddCookie(h.cookie)
	r.Header.Set("X-CSRF-Token", h.csrf)
	if w := serve(h.s.SecureHandler(), r); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site start: %d", w.Code)
	}
	if w := h.do("GET", "/api/pair/start", "", false); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET start: %d", w.Code)
	}
	if len(f.started) != 0 || f.cancels != 0 {
		t.Fatal("pairing reached without a session, CSRF token or same origin")
	}
}

func TestPairStartAndCancel(t *testing.T) {
	h := newReviewHarness(t, nil)
	f := &fakePairing{status: pair.Status{State: pair.StateIdle}}
	h.s.cfg.Pairing = f
	w := h.do("POST", "/api/pair/start", `{"server_name":"nas"}`, true)
	var s pair.Status
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &s) != nil || s.State != pair.StatePending || s.Code != "ABCDEFGHJK" || len(f.started) != 1 || f.started[0] != "nas" {
		t.Fatalf("start %d %s", w.Code, w.Body)
	}
	w = h.do("GET", "/api/pair/status", "", false)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &s) != nil || s.State != pair.StatePending {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	w = h.do("POST", "/api/pair/cancel", "", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &s) != nil || s.State != pair.StateIdle || f.cancels != 1 {
		t.Fatalf("cancel %d %s", w.Code, w.Body)
	}
	for _, body := range []string{`{"server_name":1}`, `{"name":"x"}`, `{"server_name":"a"} {}`, `x`} {
		if w := h.do("POST", "/api/pair/start", body, true); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if len(f.started) != 1 {
		t.Fatal("bad body reached pairing")
	}
}

func TestPairStartErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		msg  string
	}{
		{pair.ErrPaired, http.StatusConflict, "This client is already paired"},
		{pair.ErrInvalidName, http.StatusBadRequest, "Invalid server name (must be 1-100 characters)"},
		{&pair.Error{Text: "Pairing is paused."}, http.StatusBadGateway, "Pairing is paused."},
		{errors.New("secret detail"), http.StatusInternalServerError, "Could not start pairing"},
	}
	for _, c := range cases {
		h := newReviewHarness(t, nil)
		h.s.cfg.Pairing = &fakePairing{err: c.err}
		w := h.do("POST", "/api/pair/start", `{"server_name":"nas"}`, true)
		if w.Code != c.code || errorOf(t, w.Body.String()) != c.msg {
			t.Errorf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
}

func TestPairUnavailableWithoutKeystore(t *testing.T) {
	h := newReviewHarness(t, nil)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/pair/status", ""}, {"POST", "/api/pair/start", `{"server_name":"nas"}`}, {"POST", "/api/pair/cancel", ""},
	} {
		if w := h.do(c.method, c.path, c.body, true); w.Code != http.StatusServiceUnavailable || errorOf(t, w.Body.String()) == "" {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
}

// The page never puts the pairing code in a link; the owner types it.
func TestPairPageNeverLinksTheCode(t *testing.T) {
	for _, f := range []string{"static/app.js", "static/index.html"} {
		b, err := staticFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "code=") || strings.Contains(string(b), "Approve only if") {
			t.Errorf("%s links the code or claims the approval page shows the key", f)
		}
	}
}
