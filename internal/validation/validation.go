// Package validation provides input validation utilities
package validation

import (
	"encoding/json"
	"regexp"
	"strings"
)

// validHostChars matches valid hostname/IP characters: letters, digits, dots, hyphens, colons (IPv6), brackets
var validHostChars = regexp.MustCompile(`^[a-zA-Z0-9.\-:\[\]]+$`)

// controlChars matches ASCII control characters (0x00-0x1F and 0x7F)
var controlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// IsValidHost validates a service host format.
// The host is used by the Go client to forward FRP traffic to a local service.
// Validates format only: no control chars, null bytes, or injection vectors.
func IsValidHost(host string) bool {
	if host == "" {
		return false
	}
	if len(host) > 255 {
		return false
	}
	// Block control characters and null bytes
	if controlChars.MatchString(host) {
		return false
	}
	// Must look like a hostname or IP (letters, digits, dots, hyphens, colons for IPv6)
	if !validHostChars.MatchString(host) {
		return false
	}
	return true
}

// IsValidPort validates a port number (1-65535)
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// IsValidServiceName validates a service name
func IsValidServiceName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if len(name) > 100 {
		return false
	}
	return true
}

// ParseAPIError extracts a user-friendly error message from an API response body.
// Returns a sanitized message suitable for display to users.
func ParseAPIError(respBody []byte, statusCode int) string {
	// Try to parse as JSON error response
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respBody, &errResp); err == nil {
		// Prefer "error" field, fall back to "message"
		if errResp.Error != "" {
			return sanitizeMessage(errResp.Error)
		}
		if errResp.Message != "" {
			return sanitizeMessage(errResp.Message)
		}
	}

	// Generic fallback based on status code
	switch statusCode {
	case 400:
		return "Invalid request"
	case 401:
		return "Authentication required"
	case 403:
		return "Access denied"
	case 404:
		return "Not found"
	case 409:
		return "Conflict"
	case 429:
		return "Too many requests"
	case 500, 502, 503, 504:
		return "Server error"
	default:
		return "Request failed"
	}
}

// sanitizeMessage limits message length and removes potentially sensitive content
func sanitizeMessage(msg string) string {
	// Limit length to prevent huge error messages
	const maxLen = 200
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	// Remove control characters
	msg = controlChars.ReplaceAllString(msg, "")
	return strings.TrimSpace(msg)
}
