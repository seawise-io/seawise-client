package controlplane

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultTransportUsesProxyFromEnvironment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		seen <- strings.TrimSpace(line)
	}()
	env := map[string]string{"HTTPS_PROXY": "http://" + ln.Addr().String()}
	c, err := New(Config{
		BaseURL: "https://api.example.invalid", Token: func() string { return token },
		Getenv: func(k string) string { return env[k] },
		Sleep:  func(context.Context, time.Duration) error { return context.Canceled },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.Heartbeat(ctx, serverID, HeartbeatRequest{})
	select {
	case got := <-seen:
		if got != "CONNECT api.example.invalid:443 HTTP/1.1" {
			t.Fatalf("proxy saw %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not go through the proxy")
	}
}

// connectProxy answers CONNECT with status, then hands the client
// connection to after (nil closes it).
func connectProxy(t *testing.T, status string, after func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						c.Close()
						return
					}
					if line == "\r\n" {
						break
					}
				}
				fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", status)
				if after == nil {
					c.Close()
					return
				}
				after(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func proxiedClient(t *testing.T, proxy string, roots *x509.CertPool) *Client {
	t.Helper()
	env := map[string]string{"HTTPS_PROXY": proxy}
	getenv := func(k string) string { return env[k] }
	c, err := New(Config{
		BaseURL: "https://api.example.invalid", Token: func() string { return token },
		Getenv:     getenv,
		HTTPClient: &http.Client{Transport: NewTransport(getenv, roots)},
		Sleep:      func(context.Context, time.Duration) error { return context.Canceled },
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProxyCredentialsNotInErrors(t *testing.T) {
	closed := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().String()
	}()
	for name, addr := range map[string]string{
		"refused": closed,
		"407":     connectProxy(t, "407 Proxy Authentication Required", nil),
		"502":     connectProxy(t, "502 Bad Gateway", nil),
	} {
		t.Run(name, func(t *testing.T) {
			c := proxiedClient(t, "http://alice:Pr0xy%40Pass@"+addr, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := c.Heartbeat(ctx, serverID, HeartbeatRequest{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if KindOf(err) != Transient {
				t.Fatalf("kind = %v", KindOf(err))
			}
			for _, s := range []string{"Pr0xy", "Pass", "alice"} {
				if strings.Contains(err.Error(), s) {
					t.Fatalf("error leaks proxy credentials: %v", err)
				}
			}
		})
	}
}

// TestProxyCannotIntercept: a proxy that answers the TLS handshake itself
// is refused; the request is never sent to it.
func TestProxyCannotIntercept(t *testing.T) {
	real := httptest.NewTLSServer(http.NotFoundHandler())
	defer real.Close()
	roots := x509.NewCertPool()
	roots.AddCert(real.Certificate())

	mitm := httptest.NewUnstartedServer(http.NotFoundHandler())
	mitm.StartTLS()
	defer mitm.Close()
	cert := mitm.TLS.Certificates[0]
	sawRequest := make(chan struct{}, 1)
	addr := connectProxy(t, "200 Connection established", func(c net.Conn) {
		defer c.Close()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
		if tc.Handshake() != nil {
			return
		}
		buf := make([]byte, 1)
		if n, _ := tc.Read(buf); n > 0 {
			sawRequest <- struct{}{}
		}
	})
	c := proxiedClient(t, "http://"+addr, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.Heartbeat(ctx, serverID, HeartbeatRequest{})
	if err == nil || KindOf(err) != Transient {
		t.Fatalf("heartbeat through an intercepting proxy: %v", err)
	}
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if !errors.As(err, &unknown) && !errors.As(err, &hostErr) && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("not a certificate failure: %v", err)
	}
	select {
	case <-sawRequest:
		t.Fatal("request reached the intercepting proxy")
	case <-time.After(200 * time.Millisecond):
	}
}
