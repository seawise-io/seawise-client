// Package netproxy picks the outbound proxy for a host from the usual
// HTTPS_PROXY, HTTP_PROXY and NO_PROXY variables. It is shared by the
// control-plane client and the frpc config, so both follow one rule.
package netproxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Getenv func(string) string

// Variable orders. Upper case wins over lower case.
var (
	HTTPS = []string{"HTTPS_PROXY", "https_proxy"}
	HTTP  = []string{"HTTP_PROXY", "http_proxy"}
	// Tunnel is for non-HTTP connections such as frpc to frps.
	Tunnel = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}
)

var ErrScheme = errors.New("unsupported proxy scheme")

// ForHost returns the proxy for host:port from the first set variable in
// vars, or nil when none is set or NO_PROXY matches.
func ForHost(getenv Getenv, host string, port int, vars ...string) (*url.URL, error) {
	raw := ""
	for _, k := range vars {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			raw = v
			break
		}
	}
	if raw == "" || bypass(getenv, host, port) {
		return nil, nil
	}
	return parse(raw)
}

// CheckScheme refuses a proxy whose scheme is not in allowed.
func CheckScheme(u *url.URL, allowed ...string) error {
	for _, s := range allowed {
		if u.Scheme == s {
			return nil
		}
	}
	return fmt.Errorf("%w %q", ErrScheme, u.Scheme)
}

// Func is an http.Transport Proxy function that reads the environment on
// every request. Loopback hosts are never proxied.
func Func(getenv Getenv) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		host := r.URL.Hostname()
		if isLoopback(host) {
			return nil, nil
		}
		port, _ := strconv.Atoi(r.URL.Port())
		vars := HTTP
		if r.URL.Scheme == "https" {
			vars = HTTPS
			if port == 0 {
				port = 443
			}
		} else if port == 0 {
			port = 80
		}
		return ForHost(getenv, host, port, vars...)
	}
}

func parse(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid proxy URL")
	}
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// bypass applies NO_PROXY: "*", domain suffixes with or without a leading
// dot, IP addresses and CIDR ranges, each with an optional port.
func bypass(getenv Getenv, host string, port int) bool {
	list := getenv("NO_PROXY")
	if list == "" {
		list = getenv("no_proxy")
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	ip, ipErr := netip.ParseAddr(host)
	for _, entry := range strings.Split(list, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		if p, err := netip.ParsePrefix(entry); err == nil {
			if ipErr == nil && p.Contains(ip.Unmap()) {
				return true
			}
			continue
		}
		name, entryPort := entry, 0
		if h, ps, err := net.SplitHostPort(entry); err == nil {
			n, err := strconv.Atoi(ps)
			if err != nil {
				continue
			}
			name, entryPort = h, n
		}
		name = strings.Trim(name, "[]")
		if entryPort != 0 && entryPort != port {
			continue
		}
		if a, err := netip.ParseAddr(name); err == nil {
			if ipErr == nil && a.Unmap() == ip.Unmap() {
				return true
			}
			continue
		}
		name = strings.TrimSuffix(strings.TrimPrefix(name, "."), ".")
		if name != "" && (host == name || strings.HasSuffix(host, "."+name)) {
			return true
		}
	}
	return false
}
