package adminui

import (
	"net"
	"net/netip"
	"os"
	"strings"
)

// normalizeHost returns the lower-case host name of a Host header value
// without port or trailing dot, or "" if it is not a plain host.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	} else if strings.Contains(h, ":") && !isIP(h) {
		return ""
	}
	h = strings.TrimSuffix(h, ".")
	if isIP(h) {
		return h
	}
	if !validDNSName(h) {
		return ""
	}
	return h
}

func isIP(h string) bool {
	a, err := netip.ParseAddr(h)
	return err == nil && a.Zone() == ""
}

// hostAllowed accepts names a public DNS rebinding cannot point here: IP
// literals, localhost, mDNS .local names, and names the operator listed
// (including this machine's hostname).
func hostAllowed(raw string, extra map[string]bool) bool {
	h := normalizeHost(raw)
	switch {
	case h == "":
		return false
	case isIP(h), h == "localhost", strings.HasSuffix(h, ".local") && len(h) > len(".local"):
		return true
	}
	return extra[h]
}

// AllowedHostsFromEnv reads SEAWISE_ALLOWED_HOSTS (comma separated).
func AllowedHostsFromEnv() []string {
	var out []string
	for _, p := range strings.Split(os.Getenv("SEAWISE_ALLOWED_HOSTS"), ",") {
		if h := normalizeHost(p); h != "" {
			out = append(out, h)
		}
	}
	return out
}
