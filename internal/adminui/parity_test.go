package adminui

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/seawise/client/internal/store"
)

func TestReadyz(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	read := func(h http.Handler, r *http.Request) (int, map[string]any) {
		w := serve(h, r)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	if code, m := read(s.PlainHandler(), req("GET", "/readyz", "localhost")); code != http.StatusServiceUnavailable || m["status"] != "not_ready" {
		t.Fatalf("no readiness func: %d %v", code, m)
	}
	for _, c := range []struct {
		r    Readiness
		code int
	}{{Readiness{}, 503}, {Readiness{Paired: true}, 503}, {Readiness{TunnelUp: true}, 503}, {Readiness{Paired: true, TunnelUp: true}, 200}} {
		s.cfg.Ready = func(context.Context) Readiness { return c.r }
		code, m := read(s.PlainHandler(), req("GET", "/readyz", "localhost"))
		if code != c.code || m["paired"] != c.r.Paired || m["tunnel_up"] != c.r.TunnelUp || m["version"] == nil {
			t.Errorf("%+v: %d %v", c.r, code, m)
		}
	}
	// With TLS on, plain HTTP answers it to loopback only, as /healthz.
	tls := newServerTLS(t, newStore(t, nil), &testClock{now: t0}, true)
	tls.cfg.Ready = func(context.Context) Readiness { return Readiness{Paired: true, TunnelUp: true} }
	r := req("GET", "/readyz", "127.0.0.1:8082")
	r.RemoteAddr = "127.0.0.1:5555"
	if code, _ := read(tls.PlainHandler(), r); code != http.StatusOK {
		t.Fatalf("loopback readyz %d", code)
	}
	if code, _ := read(tls.PlainHandler(), req("GET", "/readyz", "192.168.1.10:8082")); code == http.StatusOK {
		t.Fatal("LAN peer got plain readyz")
	}
	if code, _ := read(tls.SecureHandler(), req("GET", "/readyz", "192.168.1.10:8082")); code != http.StatusOK {
		t.Fatal("readyz over HTTPS")
	}
}

func TestTrustProxy(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	r := req("POST", "/api/auth/login", "nas")
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 198.51.100.7")
	if got := s.clientIP(r); got != "127.0.0.1" {
		t.Fatalf("proxy headers used while off: %s", got)
	}
	s.cfg.TrustProxy = true
	if got := s.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("not the entry the proxy added: %s", got)
	}
	for xff, want := range map[string]string{"": "127.0.0.1", "garbage": "127.0.0.1", "203.0.113.5, 127.0.0.1": forwardedLoopback, "::1": forwardedLoopback} {
		r.Header.Set("X-Forwarded-For", xff)
		if got := s.clientIP(r); got != want || isLoopbackIP(got) != (want == "127.0.0.1") {
			t.Errorf("%q: %s", xff, got)
		}
	}
	// Two header lines: the last line's last entry is the one the proxy added.
	r.Header.Del("X-Forwarded-For")
	r.Header.Add("X-Forwarded-For", "198.51.100.9")
	r.Header.Add("X-Forwarded-For", "203.0.113.5, 192.0.2.44")
	if got := s.clientIP(r); got != "192.0.2.44" {
		t.Fatalf("two header lines: %s", got)
	}
	// The origin check follows X-Forwarded-Proto only when trusted.
	token, csrf := s.sess.create()
	logout := func() int {
		r := req("POST", "/api/auth/logout", "nas.example")
		r.Header.Set("Origin", "https://nas.example")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
		return serve(s.PlainHandler(), r).Code
	}
	s.cfg.AllowedHosts = nil
	s.hosts["nas.example"] = true
	s.cfg.TrustProxy = false
	if code := logout(); code != http.StatusForbidden {
		t.Fatalf("https origin over plain HTTP without trust: %d", code)
	}
	s.cfg.TrustProxy = true
	if code := logout(); code != http.StatusOK {
		t.Fatalf("https origin behind a trusted proxy: %d", code)
	}
}

func TestAppListShowsRemovedFromAccount(t *testing.T) {
	h := newReviewHarness(t, []store.Target{
		{LocalID: "a", Name: "Media", Host: "10.0.0.1", Port: 80, Disabled: true, RemovedFromAccount: true, IconURL: "https://cdn.example/m.png", Source: store.SourceLocal},
		{LocalID: "b", Name: "Notes", Host: "10.0.0.2", Port: 81, Disabled: true, Source: store.SourceLocal},
	})
	w := h.do("GET", "/api/apps", "", false)
	var out struct {
		Apps []appRow `json:"apps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Apps) != 2 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if a := out.Apps[0]; !a.RemovedFromAccount || a.Status != "disabled" || a.IconURL != "https://cdn.example/m.png" {
		t.Fatalf("%+v", a)
	}
	if out.Apps[1].RemovedFromAccount || strings.Contains(w.Body.String(), `"removed_from_account":false`) {
		t.Fatalf("%s", w.Body)
	}
	if h.act(`{"local_id":"a","action":"enable"}`, true) != http.StatusOK {
		t.Fatal("re-enable")
	}
	if tg := h.st.State().Targets[0]; tg.Disabled || tg.RemovedFromAccount {
		t.Fatalf("re-enabled: %+v", tg)
	}
}
