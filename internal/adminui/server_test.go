package adminui

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
	"golang.org/x/crypto/bcrypt"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func newStore(t *testing.T, upgraded *time.Time) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Update(func(s *store.State) error { s.UpgradedAt = upgraded; return nil }); err != nil {
		t.Fatal(err)
	}
	return st
}

func newServer(t *testing.T, st *store.Store, clk *testClock) *Server {
	t.Helper()
	auth, err := NewAuth(AuthConfig{Store: st, Now: clk.Now, BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Store: st, Auth: auth, Now: clk.Now, Hostname: "nas", AllowedHosts: []string{"seawise.internal.example"},
		Status: func(context.Context) any { return map[string]string{"state": "ok"} }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func req(method, target, host string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	r.RemoteAddr = "192.168.1.50:40000"
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSecurityHeaders(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	for _, h := range []http.Handler{s.SecureHandler(), s.PlainHandler()} {
		w := serve(h, req("GET", "/", "192.168.1.10:8082"))
		hd := w.Header()
		if !strings.Contains(hd.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
			strings.Contains(hd.Get("Content-Security-Policy"), "unsafe-inline") ||
			hd.Get("X-Frame-Options") != "DENY" || hd.Get("X-Content-Type-Options") != "nosniff" ||
			hd.Get("Referrer-Policy") != "no-referrer" || hd.Get("Strict-Transport-Security") != "" {
			t.Fatalf("headers %v", hd)
		}
	}
}

func TestHostAllowlistEveryMethod(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"} {
		for _, host := range []string{"evil.example", "evil.example:8082", "nas.evil.example", "", "local", "[::1", "127.0.0.1.nip.io"} {
			r := req(m, "/healthz", host)
			r.Header.Set("Origin", "https://"+host)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			if w := serve(s.SecureHandler(), r); w.Code != http.StatusMisdirectedRequest {
				t.Errorf("secure %s %q: %d", m, host, w.Code)
			}
			if w := serve(s.PlainHandler(), req(m, "/", host)); w.Code != http.StatusMisdirectedRequest {
				t.Errorf("plain %s %q: %d", m, host, w.Code)
			}
		}
	}
	for _, host := range []string{"192.168.1.10:8082", "[fe80::1]:8082", "localhost:8082", "nas", "nas:8082", "NAS.local", "seawise.internal.example:8082", "nas."} {
		if w := serve(s.SecureHandler(), req("GET", "/healthz", host)); w.Code != http.StatusOK {
			t.Errorf("allowed host %q: %d", host, w.Code)
		}
	}
}

func TestRedirectWindow(t *testing.T) {
	up := t0
	clk := &testClock{now: t0.Add(24 * time.Hour)}
	s := newServer(t, newStore(t, &up), clk)
	w := serve(s.PlainHandler(), req("GET", "/some/path?x=1", "192.168.1.10:8082"))
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://192.168.1.10:8082/some/path?x=1" {
		t.Fatalf("redirect %d %q", w.Code, w.Header().Get("Location"))
	}
	clk.now = t0.Add(RedirectWindow)
	w = serve(s.PlainHandler(), req("GET", "/", "192.168.1.10:8082"))
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "https://192.168.1.10:8082/") {
		t.Fatalf("after window %d %q", w.Code, w.Body.String())
	}
}

func TestNewInstallShowsNotice(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	w := serve(s.PlainHandler(), req("GET", "/", "nas.local:8082"))
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
		t.Fatalf("new install %d", w.Code)
	}
}

func TestPlainPostNotProcessed(t *testing.T) {
	up := t0
	s := newServer(t, newStore(t, &up), &testClock{now: t0})
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		w := serve(s.PlainHandler(), req(m, "/api/auth/login", "192.168.1.10:8082"))
		if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
			t.Fatalf("%s over plain: %d", m, w.Code)
		}
	}
}

func TestRedirectDisallowedHost(t *testing.T) {
	up := t0
	s := newServer(t, newStore(t, &up), &testClock{now: t0})
	w := serve(s.PlainHandler(), req("GET", "/", "evil.example"))
	if w.Code != http.StatusMisdirectedRequest || w.Header().Get("Location") != "" {
		t.Fatalf("open redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestNoticeEscapesHost(t *testing.T) {
	// Only allowlisted hosts reach the notice, but it is escaped anyway.
	if strings.Contains(renderNotice(`<x>`), "<x>") {
		t.Fatal("notice not escaped")
	}
}

func renderNotice(host string) string {
	var b strings.Builder
	_ = noticeTmpl.Execute(&b, host)
	return b.String()
}

func TestHealthzLoopbackOnly(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	r := req("GET", "/healthz", "127.0.0.1:8082")
	r.RemoteAddr = "127.0.0.1:5555"
	if w := serve(s.PlainHandler(), r); w.Code != http.StatusOK {
		t.Fatalf("loopback healthz %d", w.Code)
	}
	r = req("GET", "/healthz", "127.0.0.1:8082")
	r.RemoteAddr = "[::ffff:127.0.0.1]:5555"
	if w := serve(s.PlainHandler(), r); w.Code != http.StatusOK {
		t.Fatalf("mapped loopback healthz %d", w.Code)
	}
	r = req("GET", "/healthz", "192.168.1.10:8082")
	if w := serve(s.PlainHandler(), r); w.Code == http.StatusOK {
		t.Fatal("LAN peer got plain healthz")
	}
}

func TestCSRF(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	token, csrf := s.sess.create()
	const host = "192.168.1.10:8082"
	logout := func(origin, fetchSite, csrfHdr string) int {
		r := req("POST", "/api/auth/logout", host)
		r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		if csrfHdr != "" {
			r.Header.Set("X-CSRF-Token", csrfHdr)
		}
		return serve(s.SecureHandler(), r).Code
	}
	cases := []struct {
		origin, site, csrf string
		want               int
	}{
		{"", "", csrf, 403},
		{"https://evil.example", "", csrf, 403},
		{"http://" + host, "", csrf, 403},
		{"null", "", csrf, 403},
		{"", "cross-site", csrf, 403},
		{"https://" + host, "", "", 403},
		{"https://" + host, "", "wrong", 403},
		{"https://" + host, "", csrf, 200},
	}
	for i, c := range cases {
		if got := logout(c.origin, c.site, c.csrf); got != c.want {
			t.Errorf("case %d: %d want %d", i, got, c.want)
		}
	}
	token, csrf = s.sess.create()
	if got := logout("", "same-origin", csrf); got != 200 {
		t.Fatalf("same-origin fetch: %d", got)
	}
}

func TestStatusNeedsSession(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	if w := serve(s.SecureHandler(), req("GET", "/api/status", "localhost")); w.Code != 401 {
		t.Fatalf("no session: %d", w.Code)
	}
	token, _ := s.sess.create()
	r := req("GET", "/api/status", "localhost")
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	if w := serve(s.SecureHandler(), r); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"ok"`) {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
}

func TestStaticNoInlineScript(t *testing.T) {
	s := newServer(t, newStore(t, nil), &testClock{now: t0})
	w := serve(s.SecureHandler(), req("GET", "/", "localhost"))
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "onclick") {
		t.Fatalf("index: %d", w.Code)
	}
	if w := serve(s.SecureHandler(), req("GET", "/static/app.js", "localhost")); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") {
		t.Fatalf("app.js: %d", w.Code)
	}
	if w := serve(s.SecureHandler(), req("GET", "/static/..%2fserver.go", "localhost")); w.Code == 200 {
		t.Fatal("path traversal")
	}
}

func TestSessionsCapAndExpiry(t *testing.T) {
	clk := &testClock{now: t0}
	ss := newSessions(clk.Now)
	first, _ := ss.create()
	for i := 0; i < MaxSessions; i++ {
		clk.now = clk.now.Add(time.Second)
		ss.create()
	}
	if ss.count() != MaxSessions {
		t.Fatalf("count %d", ss.count())
	}
	if _, ok := ss.lookup(first); ok {
		t.Fatal("oldest not evicted")
	}
	tok, _ := ss.create()
	clk.now = clk.now.Add(SessionTTL)
	if _, ok := ss.lookup(tok); ok {
		t.Fatal("expired session valid")
	}
}

func TestCookieFlags(t *testing.T) {
	w := httptest.NewRecorder()
	setSessionCookie(w, "v")
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-seawise_session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %+v", c)
	}
}

// TestOnePortServesBoth runs the real listener: TLS and plain HTTP on one port.
func TestOnePortServesBoth(t *testing.T) {
	up := t0
	st := newStore(t, &up)
	s := newServer(t, st, &testClock{now: t0})
	info, err := EnsureCert(t.TempDir(), []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln, info.Cert) }()
	defer func() { cancel(); <-done }()
	addr := ln.Addr().String()

	pool := x509.NewCertPool()
	pool.AddCert(info.Cert.Leaf)
	hc := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for i := 0; i < 3; i++ {
		resp, err := hc.Get("https://" + addr + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), "ok") || resp.TLS == nil {
			t.Fatalf("https healthz %d %s", resp.StatusCode, b)
		}
		resp, err = hc.Get("http://" + addr + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.TLS != nil {
			t.Fatalf("plain healthz %d", resp.StatusCode)
		}
		resp, err = hc.Get("http://" + addr + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://"+addr+"/" {
			t.Fatalf("plain / %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}
