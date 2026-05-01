package validation

import (
	"net"
	"strings"
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
	net.ParseIP("192.0.0.192"),     // Oracle Cloud
	net.ParseIP("100.100.100.200"), // Alibaba Cloud
}

// blockedMetadataHostnames are DNS names that resolve to provider metadata.
var blockedMetadataHostnames = []string{
	"metadata.google.internal",
	"metadata.google",
}

// isCloudMetadata checks if host points to cloud metadata endpoints.
// Strips the optional :port suffix before comparing.
func isCloudMetadata(host string) bool {
	lower := strings.ToLower(host)
	// Strip [::1]:port style brackets first
	if h, _, err := net.SplitHostPort(lower); err == nil {
		lower = h
	}

	for _, name := range blockedMetadataHostnames {
		if lower == name || strings.HasSuffix(lower, "."+name) {
			return true
		}
	}

	if ip := net.ParseIP(lower); ip != nil {
		for _, blocked := range blockedMetadataIPs {
			if blocked != nil && ip.Equal(blocked) {
				return true
			}
		}
	}

	return false
}

// ValidateServiceHost checks if a host is safe to expose via tunnel.
// Blocks cloud metadata endpoints; allows everything else.
func ValidateServiceHost(host string) error {
	if host == "" {
		return &BlockedHostError{Host: host, Reason: "host cannot be empty"}
	}

	if isCloudMetadata(host) {
		return &BlockedHostError{
			Host:   host,
			Reason: "cloud metadata endpoints cannot be exposed (security risk)",
		}
	}

	return nil
}
