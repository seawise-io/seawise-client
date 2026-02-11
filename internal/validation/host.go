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

// isCloudMetadata checks if host points to cloud metadata endpoints
// These are blocked because exposing them could leak cloud credentials
func isCloudMetadata(host string) bool {
	lower := strings.ToLower(host)

	// AWS/GCP/Azure metadata IP (with optional port)
	if lower == "169.254.169.254" || strings.HasPrefix(lower, "169.254.169.254:") {
		return true
	}

	// GCP metadata hostnames
	metadataHosts := []string{
		"metadata.google.internal",
		"metadata.google",
	}

	for _, m := range metadataHosts {
		if lower == m || strings.HasSuffix(lower, "."+m) {
			return true
		}
	}

	return false
}

// ValidateServiceHost checks if a host is safe to expose via tunnel.
//
// SeaWise is designed to let users expose their local services to the web.
// Users should be able to expose:
// - localhost services (the main use case)
// - Docker containers (host.docker.internal)
// - Other machines on their network (NAS, media servers, etc.)
//
// We only block truly dangerous endpoints:
// - Cloud metadata endpoints (169.254.169.254) - could leak credentials
func ValidateServiceHost(host string) error {
	if host == "" {
		return &BlockedHostError{Host: host, Reason: "host cannot be empty"}
	}

	// Block cloud metadata endpoints - these could leak cloud credentials
	if isCloudMetadata(host) {
		return &BlockedHostError{
			Host:   host,
			Reason: "cloud metadata endpoints cannot be exposed (security risk)",
		}
	}

	// Try to parse as IP and check for metadata IP
	ip := net.ParseIP(host)
	if ip != nil {
		// Block the metadata IP specifically
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return &BlockedHostError{
				Host:   host,
				Reason: "cloud metadata endpoints cannot be exposed (security risk)",
			}
		}
	}

	// All other hosts are allowed - users know their network
	return nil
}
