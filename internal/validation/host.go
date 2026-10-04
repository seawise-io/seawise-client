package validation

import (
	"context"
	"net"
	"strings"
	"time"
)

// BlockedHostError indicates a host was blocked by security validation
type BlockedHostError struct {
	Host   string
	Reason string
}

func (e *BlockedHostError) Error() string {
	return "blocked: " + e.Reason
}

// blockedMetadataIPs are well-known cloud metadata endpoints across providers.
// Both IPv4 and IPv6 forms are listed; net.IP.Equal handles IPv4-mapped IPv6.
var blockedMetadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"), // AWS, Azure, DigitalOcean, OVH, common link-local
	net.ParseIP("fd00:ec2::254"),   // AWS IPv6 IMDS
	net.ParseIP("192.0.0.192"),     // Oracle Cloud legacy Compute Classic (modern OCI uses 169.254.169.254 above)
	net.ParseIP("100.100.100.200"), // Alibaba Cloud
}

// blockedMetadataHostnames are DNS names that resolve to provider metadata.
var blockedMetadataHostnames = []string{
	"metadata.google.internal",
	"metadata.google",
}

var blockedNets = []*net.IPNet{
	mustCIDR("169.254.0.0/16"),
	mustCIDR("fe80::/10"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

const resolveTimeout = time.Second

var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func normalizeHost(host string) string {
	lower := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(lower); err == nil {
		lower = h
	} else if len(lower) >= 2 && lower[0] == '[' && lower[len(lower)-1] == ']' {
		lower = lower[1 : len(lower)-1]
	}
	return strings.TrimSuffix(lower, ".")
}

func isBlockedIP(ip net.IP) bool {
	for _, blocked := range blockedMetadataIPs {
		if ip.Equal(blocked) {
			return true
		}
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isCloudMetadata(host string) bool {
	h := normalizeHost(host)
	for _, name := range blockedMetadataHostnames {
		if h == name || strings.HasSuffix(h, "."+name) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		return isBlockedIP(ip)
	}
	return false
}

func blockedError(host string) error {
	return &BlockedHostError{
		Host:   host,
		Reason: "cloud metadata and link-local addresses cannot be exposed (security risk)",
	}
}

func ValidateServiceHost(host string) error {
	if host == "" {
		return &BlockedHostError{Host: host, Reason: "host cannot be empty"}
	}
	if isCloudMetadata(host) {
		return blockedError(host)
	}
	return nil
}

func ValidateServiceHostResolved(host string) error {
	if err := ValidateServiceHost(host); err != nil {
		return err
	}
	h := normalizeHost(host)
	if net.ParseIP(h) != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	ips, err := lookupIP(ctx, h)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return blockedError(host)
		}
	}
	return nil
}
