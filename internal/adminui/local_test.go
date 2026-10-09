package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/store"
)

func (h *reviewHarness) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.Host = "localhost"
	r.Header.Set("Origin", "https://localhost")
	if h.cookie != nil {
		r.AddCookie(h.cookie)
	}
	if withCSRF {
		r.Header.Set("X-CSRF-Token", h.csrf)
	}
	w := httptest.NewRecorder()
	h.s.SecureHandler().ServeHTTP(w, r)
	return w
}

func TestAccessLogEndpoint(t *testing.T) {
	h := newReviewHarness(t, []store.Target{{LocalID: "a", Name: "<b>site</b>", Host: "192.168.1.5", Port: 80, Source: store.SourceLocal}})
	l, err := accesslog.Open(accesslog.Config{Dir: h.st.Dir(), Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 3; i++ {
		l.Record(accesslog.Entry{Time: t0.Add(time.Duration(i) * time.Second), App: "a", Peer: "127.0.0.1:1", Target: "192.168.1.5:80", BytesIn: int64(i), Result: accesslog.ResultOK})
	}
	l.Record(accesslog.Entry{Time: t0, App: "gone", Peer: "127.0.0.1:1", Target: "x:1", Result: accesslog.ResultBusy})
	l.Flush()
	h.s.cfg.AccessLog = l

	w := h.do("GET", "/api/access-log?limit=2", "", false)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "<b>") || !strings.Contains(w.Body.String(), `\u003cb\u003esite`) {
		t.Fatalf("name not escaped: %s", w.Body)
	}
	var page struct {
		Entries []struct {
			Name    string `json:"name"`
			App     string `json:"app"`
			BytesIn int64  `json:"bytes_in"`
		} `json:"entries"`
		Next string `json:"next"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || page.Next == "" || page.Entries[0].App != "gone" || page.Entries[0].Name != "" || page.Entries[1].Name != "<b>site</b>" {
		t.Fatalf("page = %+v", page)
	}
	w = h.do("GET", "/api/access-log?limit=2&cursor="+page.Next, "", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"bytes_in":1`) {
		t.Fatalf("second page %d %s", w.Code, w.Body)
	}
	for _, q := range []string{"?cursor=../x", "?limit=abc", "?limit=-1"} {
		if w := h.do("GET", "/api/access-log"+q, "", false); w.Code != 400 {
			t.Errorf("%s: status %d", q, w.Code)
		}
	}
	h.cookie = nil
	if w := h.do("GET", "/api/access-log", "", false); w.Code != 401 {
		t.Fatalf("no session: %d", w.Code)
	}
}

func TestKillSwitchEndpoint(t *testing.T) {
	h := newReviewHarness(t, nil)
	if w := h.do("POST", "/api/kill-switch", `{"on":true}`, true); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("without a handler: %d", w.Code)
	}
	var calls []bool
	h.s.cfg.KillSwitch = func(_ context.Context, on bool) error { calls = append(calls, on); return nil }
	if w := h.do("POST", "/api/kill-switch", `{"on":true}`, false); w.Code != 403 {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	for _, body := range []string{`{}`, `{"on":"yes"}`, `{"on":true,"x":1}`, `nope`} {
		if w := h.do("POST", "/api/kill-switch", body, true); w.Code != 400 {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	if w := h.do("POST", "/api/kill-switch", `{"on":true}`, true); w.Code != 200 {
		t.Fatalf("on: %d", w.Code)
	}
	if w := h.do("POST", "/api/kill-switch", `{"on":false}`, true); w.Code != 200 {
		t.Fatalf("off: %d", w.Code)
	}
	if len(calls) != 2 || !calls[0] || calls[1] {
		t.Fatalf("calls = %v", calls)
	}
	h.s.cfg.KillSwitch = func(context.Context, bool) error { return errors.New("disk full") }
	if w := h.do("POST", "/api/kill-switch", `{"on":true}`, true); w.Code != 500 || strings.Contains(w.Body.String(), "disk") {
		t.Fatalf("error: %d %s", w.Code, w.Body)
	}
}

func TestPublicToggleActions(t *testing.T) {
	now := t0
	h := newReviewHarness(t, []store.Target{
		{LocalID: "a", Name: "site", Host: "192.168.1.5", Port: 80, ConfirmedAt: &now, Source: store.SourceLocal, ServerPublic: true},
	})
	changed := 0
	h.s.cfg.OnTargetsChanged = func(context.Context) { changed++ }
	if body := h.list(); !strings.Contains(body, `"server_public":true`) || !strings.Contains(body, `"public":false`) {
		t.Fatalf("conflict not listed: %s", body)
	}
	if code := h.act(`{"local_id":"a","action":"make_public"}`, true); code != 200 {
		t.Fatalf("make_public %d", code)
	}
	if !h.target("a").IsPublicLocally() || changed != 1 {
		t.Fatal("toggle not saved")
	}
	if code := h.act(`{"local_id":"a","action":"make_private"}`, true); code != 200 {
		t.Fatalf("make_private %d", code)
	}
	if p := h.target("a").Public; p == nil || *p {
		t.Fatal("private not saved")
	}
	if code := h.act(`{"local_id":"a","action":"make_public"}`, false); code != 403 {
		t.Fatalf("without CSRF %d", code)
	}
}

func TestUIUsesTextContentOnly(t *testing.T) {
	for _, name := range []string{"static/app.js", "static/index.html"} {
		b, err := staticFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s uses %s", name, bad)
			}
		}
	}
	b, _ := staticFS.ReadFile("static/app.js")
	for _, want := range []string{"/api/access-log", "/api/kill-switch", "make_public", "make_private"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("app.js does not use %s", want)
		}
	}
}

func TestUIShowsUpdateNotice(t *testing.T) {
	html, _ := staticFS.ReadFile("static/index.html")
	if !strings.Contains(string(html), `id="update"`) {
		t.Error("index.html has no update notice element")
	}
	js, _ := staticFS.ReadFile("static/app.js")
	for _, want := range []string{"s.updates", "u.available.version", `u.state === "expired"`, "does not update itself"} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js does not use %s", want)
		}
	}
}
