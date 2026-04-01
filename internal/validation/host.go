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

// isCloudMetadata checks if host points to cloud metadata endpoints.
func isCloudMetadata(host string) bool {
	lower := strings.ToLower(host)

	if lower == "169.254.169.254" || strings.HasPrefix(lower, "169.254.169.254:") {
		return true
	}

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

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return &BlockedHostError{
				Host:   host,
				Reason: "cloud metadata endpoints cannot be exposed (security risk)",
			}
		}
	}

	return nil
}
