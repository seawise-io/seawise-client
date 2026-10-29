package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/seawise/client/internal/netproxy"
)

const maxConnectResponse = 8 << 10

// proxy is the HTTP proxy a tunnel name is reached through.
type proxy struct {
	addr   string // host:port
	tls    bool
	host   string
	auth   string // Proxy-Authorization value, or ""
	public string // scheme://host:port, the only form ever shown
}

// proxyFor returns the HTTPS_PROXY for name, nil when none applies.
func (d *Dialer) proxyFor(name string) (*proxy, error) {
	u, err := netproxy.ForHost(d.getenv, name, 443, netproxy.HTTPS...)
	if err != nil {
		return nil, local("proxy", fmt.Errorf("%w: %w", ErrProxy, err))
	}
	if u == nil {
		return nil, nil
	}
	return parseProxy(u)
}

func parseProxy(u *url.URL) (*proxy, error) {
	p := &proxy{host: u.Hostname()}
	port := u.Port()
	switch u.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		p.tls = true
		if port == "" {
			port = "443"
		}
	default:
		return nil, local("proxy", fmt.Errorf("%w: scheme %q (http and https are supported)", ErrProxy, u.Scheme))
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, local("proxy", fmt.Errorf("%w: port", ErrProxy))
	}
	p.addr = net.JoinHostPort(p.host, port)
	p.public = u.Scheme + "://" + p.addr
	if u.User != nil {
		pass, _ := u.User.Password()
		p.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))
	}
	return p, nil
}

// connect opens a CONNECT tunnel to name:443 through the proxy. The edge
// speaks only after the agent's ClientHello, so any byte after the
// proxy's answer is refused.
func (d *Dialer) connect(ctx context.Context, p *proxy, name string) (net.Conn, error) {
	conn, err := d.dialTCP(ctx, "tcp", p.addr)
	if err != nil {
		return nil, blocked(CauseDial, "proxy_dial", fmt.Errorf("proxy %s: %w", p.public, opErr(err)))
	}
	stop := closeOnDone(ctx, conn)
	defer stop()
	if p.tls {
		tc := tls.Client(conn, &tls.Config{ServerName: p.host, RootCAs: d.cfg.ProxyRootCAs,
			MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, blocked(CauseDial, "proxy_tls", fmt.Errorf("proxy %s: %w", p.public, err))
		}
		conn = tc
	}
	target := net.JoinHostPort(name, "443")
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if p.auth != "" {
		req += "Proxy-Authorization: " + p.auth + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		_ = conn.Close()
		return nil, blocked(CauseDial, "proxy_io", fmt.Errorf("proxy %s: %w", p.public, opErr(err)))
	}
	if err := readConnectResponse(conn); err != nil {
		_ = conn.Close()
		var e *Error
		if errors.As(err, &e) {
			e.Err = fmt.Errorf("proxy %s: %w", p.public, e.Err)
			return nil, e
		}
		return nil, blocked(CauseDial, "proxy_io", fmt.Errorf("proxy %s: %w", p.public, opErr(err)))
	}
	return conn, nil
}

func readConnectResponse(conn net.Conn) error {
	buf := make([]byte, maxConnectResponse)
	n := 0
	for {
		if i := bytes.Index(buf[:n], []byte("\r\n\r\n")); i >= 0 {
			if i+4 != n {
				return blocked(CauseDial, "proxy_response", errors.New("bytes after the CONNECT answer"))
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf[:n])), nil)
			if err != nil {
				return blocked(CauseDial, "proxy_response", errors.New("malformed CONNECT answer"))
			}
			_ = resp.Body.Close()
			switch {
			case resp.StatusCode == http.StatusProxyAuthRequired:
				return blocked(CauseDial, "proxy_auth", errors.New("proxy authentication required"))
			case resp.StatusCode < 200 || resp.StatusCode > 299:
				return blocked(CauseDial, "proxy_status", fmt.Errorf("CONNECT answered %d", resp.StatusCode))
			}
			return nil
		}
		if n == len(buf) {
			return blocked(CauseDial, "proxy_response", errors.New("CONNECT answer too large"))
		}
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil && m == 0 {
			return err
		}
	}
}

// opErr drops the address details a *net.OpError adds beyond the
// operation and cause; addresses here never carry credentials, but the
// cause is what matters.
func opErr(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return fmt.Errorf("%s: %w", oe.Op, oe.Err)
	}
	return err
}
