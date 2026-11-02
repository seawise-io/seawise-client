package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// fakeProxy is an HTTP CONNECT proxy that sends every tunnel to the edge.
type fakeProxy struct {
	ln   net.Listener
	edge string
	// answer is the status line and headers sent back ("" = 200).
	answer string
	tls    *tls.Config

	mu   sync.Mutex
	reqs []string
}

func newProxy(t *testing.T, e *edgeSrv, mods ...func(*fakeProxy)) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{ln: ln, edge: e.ln.Addr().String()}
	for _, m := range mods {
		m(p)
	}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *fakeProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *fakeProxy) handle(c net.Conn) {
	defer c.Close()
	if p.tls != nil {
		tc := tls.Server(c, p.tls)
		if tc.Handshake() != nil {
			return
		}
		c = tc
	}
	br := bufio.NewReader(c)
	var req strings.Builder
	for {
		l, err := br.ReadString('\n')
		req.WriteString(l)
		if err != nil {
			return
		}
		if l == "\r\n" {
			break
		}
	}
	p.mu.Lock()
	p.reqs = append(p.reqs, req.String())
	p.mu.Unlock()
	answer := p.answer
	if answer == "" {
		answer = "HTTP/1.1 200 Connection established\r\n\r\n"
	}
	if _, err := io.WriteString(c, answer); err != nil || !strings.Contains(answer, " 200 ") {
		return
	}
	up, err := net.Dial("tcp", p.edge)
	if err != nil {
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

func (p *fakeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.reqs...)
}

func env(vars map[string]string) func(*Config) {
	return func(c *Config) { c.Getenv = func(k string) string { return vars[k] } }
}

// noDirect fails any connection that is not to the proxy.
func noDirect(t *testing.T, p *fakeProxy) func(*Config) {
	return func(c *Config) {
		c.DialTCP = func(ctx context.Context, n, addr string) (net.Conn, error) {
			if addr != p.ln.Addr().String() {
				t.Errorf("direct connection to %s", addr)
				return nil, errors.New("direct")
			}
			var d net.Dialer
			return d.DialContext(ctx, n, addr)
		}
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			t.Error("resolved through a proxy")
			return nil, errors.New("no")
		}
	}
}

func TestProxyBothCarriages(t *testing.T) {
	for _, c := range []Carriage{TLS, WebSocket} {
		t.Run(c.String(), func(t *testing.T) {
			e := newEdge(t)
			p := newProxy(t, e)
			d := e.dialer(t, env(map[string]string{"HTTPS_PROXY": "http://user:s3cret@" + p.ln.Addr().String()}), noDirect(t, p))
			s, err := d.Dial(ctx(t), testName, c)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if !s.Proxied || s.LastKnown {
				t.Fatal(s.Proxied, s.LastKnown)
			}
			echo(t, s, "through the proxy")
			want := "CONNECT tunnel-us-east.seawise.dev:443 HTTP/1.1\r\nHost: tunnel-us-east.seawise.dev:443\r\n" +
				"Proxy-Authorization: Basic dXNlcjpzM2NyZXQ=\r\n\r\n"
			if r := p.requests(); len(r) != 1 || r[0] != want {
				t.Fatalf("%q", r)
			}
		})
	}
}

func TestProxyLowerCaseAndNoAuth(t *testing.T) {
	e := newEdge(t)
	p := newProxy(t, e)
	d := e.dialer(t, env(map[string]string{"https_proxy": p.ln.Addr().String()}), noDirect(t, p))
	s, err := d.Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if r := p.requests(); len(r) != 1 || strings.Contains(r[0], "Proxy-Authorization") {
		t.Fatalf("%q", r)
	}
}

func TestProxyHTTPProxyNotUsed(t *testing.T) {
	e := newEdge(t)
	p := newProxy(t, e)
	s, err := e.dialer(t, env(map[string]string{"HTTP_PROXY": "http://" + p.ln.Addr().String()})).Dial(ctx(t), testName, TLS)
	if err != nil || s.Proxied || len(p.requests()) != 0 {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestProxyNoProxy(t *testing.T) {
	e := newEdge(t)
	p := newProxy(t, e)
	d := e.dialer(t, env(map[string]string{"HTTPS_PROXY": "http://" + p.ln.Addr().String(), "NO_PROXY": ".seawise.dev"}))
	s, err := d.Dial(ctx(t), testName, TLS)
	if err != nil || s.Proxied || len(p.requests()) != 0 {
		t.Fatal(err, len(p.requests()))
	}
	_ = s.Close()
}

func TestProxyFailures(t *testing.T) {
	const creds = "user:hunter2secret"
	cases := []struct {
		name, answer, reason string
	}{
		{"407", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n", "proxy_auth"},
		{"403", "HTTP/1.1 403 Forbidden\r\n\r\n", "proxy_status"},
		{"bytes after answer", "HTTP/1.1 200 OK\r\n\r\nX", "proxy_response"},
		{"malformed", "NOT HTTP\r\n\r\n", "proxy_response"},
		{"too large", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", maxConnectResponse) + "\r\n\r\n", "proxy_response"},
		{"closed", "HTTP/1.1 200", "proxy_io"},
		{"empty header block", "\r\n\r\n", "proxy_response"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEdge(t)
			p := newProxy(t, e, func(p *fakeProxy) { p.answer = c.answer })
			d := e.dialer(t, env(map[string]string{"HTTPS_PROXY": "http://" + creds + "@" + p.ln.Addr().String()}), noDirect(t, p))
			_, err := d.Dial(ctx(t), testName, WebSocket)
			er := asError(t, err)
			if er.Kind != Blocked || er.Cause != CauseDial || er.Reason != c.reason {
				t.Fatal(err)
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user") {
				t.Fatal("credentials in the error:", err)
			}
		})
	}
}

func TestProxyUnusable(t *testing.T) {
	e := newEdge(t)
	for _, v := range []string{"socks5://127.0.0.1:1080", "ntlm://proxy:8080", "http://proxy:99999", "http://proxy/path", "http://user:pw@proxy:0"} {
		_, err := e.dialer(t, env(map[string]string{"HTTPS_PROXY": v})).Dial(ctx(t), testName, TLS)
		if !errors.Is(err, ErrProxy) || KindOf(err) != Local || strings.Contains(err.Error(), "pw") {
			t.Error(v, err)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.accepts != 0 {
		t.Fatal("dialled")
	}
}

func TestProxyDialFailure(t *testing.T) {
	e := newEdge(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	_, err := e.dialer(t, env(map[string]string{"HTTPS_PROXY": "http://u:secretpw@" + addr})).Dial(ctx(t), testName, TLS)
	if er := asError(t, err); er.Reason != "proxy_dial" || strings.Contains(err.Error(), "secretpw") {
		t.Fatal(err)
	}
}

func TestHTTPSProxy(t *testing.T) {
	e := newEdge(t)
	cert, roots := pki(t, "localhost")
	p := newProxy(t, e, func(p *fakeProxy) { p.tls = &tls.Config{Certificates: []tls.Certificate{cert}} })
	_, port, _ := net.SplitHostPort(p.ln.Addr().String())
	d := e.dialer(t, env(map[string]string{"HTTPS_PROXY": "https://localhost:" + port}), func(c *Config) {
		c.ProxyRootCAs = roots
		c.DialTCP = func(ctx context.Context, n, addr string) (net.Conn, error) {
			if addr != "localhost:"+port {
				t.Errorf("direct connection to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, n, p.ln.Addr().String())
		}
	})
	s, err := d.Dial(ctx(t), testName, WebSocket)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, s, "inside two TLS sessions")
	_ = s.Close()
	// An https proxy with an untrusted certificate is refused.
	d = e.dialer(t, env(map[string]string{"HTTPS_PROXY": "https://localhost:" + port}), func(c *Config) {
		c.DialTCP = func(ctx context.Context, n, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, n, p.ln.Addr().String())
		}
	})
	if _, err := d.Dial(ctx(t), testName, TLS); asError(t, err).Reason != "proxy_tls" {
		t.Fatal(err)
	}
}
