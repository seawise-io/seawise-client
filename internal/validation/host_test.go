package validation

import (
	"testing"
)

func TestValidateServiceHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Allowed hosts - users can expose their local services
		{"localhost", "localhost", false},
		{"127.0.0.1", "127.0.0.1", false},
		{"ipv6 loopback", "::1", false},
		{"docker internal", "host.docker.internal", false},
		{"public hostname", "example.com", false},
		{"public IP", "8.8.8.8", false},

		// Private IPs are ALLOWED - users may want to expose NAS, media servers, etc.
		{"private 10.x", "10.0.0.1", false},
		{"private 172.16.x", "172.16.0.1", false},
		{"private 192.168.x", "192.168.1.1", false},

		// Blocked hosts - only cloud metadata is blocked
		{"empty", "", true},
		{"AWS metadata", "169.254.169.254", true},
		{"AWS metadata with port", "169.254.169.254:80", true},
		{"GCP metadata hostname", "metadata.google.internal", true},
		{"GCP metadata short", "metadata.google", true},
		{"GCP metadata subdomain", "v1.metadata.google.internal", true},
		// SEA-155: expanded coverage
		{"AWS IPv6 IMDS", "fd00:ec2::254", true},
		{"AWS IPv6 IMDS bracketed with port", "[fd00:ec2::254]:80", true},
		{"AWS IPv6 IMDS bracketed no port", "[fd00:ec2::254]", true},
		{"IPv4-mapped IPv6 metadata", "::ffff:169.254.169.254", true},
		{"Oracle Cloud metadata", "192.0.0.192", true},
		{"Alibaba Cloud metadata", "100.100.100.200", true},
		// SEA-168: trailing-dot FQDN form
		{"GCP metadata trailing dot", "metadata.google.internal.", true},
		{"GCP metadata subdomain trailing dot", "v1.metadata.google.internal.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceHost(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateServiceHost(%q) expected error, got nil", tt.host)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateServiceHost(%q) unexpected error: %v", tt.host, err)
				}
			}
		})
	}
}
