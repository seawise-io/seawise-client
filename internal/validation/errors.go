package validation

import (
	"strings"
)

// SanitizeErrorForUI returns a safe error message for display in the web UI.
func SanitizeErrorForUI(err error, fallback string) string {
	if err == nil {
		return fallback
	}

	msg := err.Error()

	if strings.Contains(msg, `{"`) || strings.Contains(msg, `{\"`) {
		return fallback
	}

	sensitivePatterns := []string{
		".go:",      // Stack traces
		"runtime/",  // Go runtime
		"goroutine", // Stack traces
		"panic:",    // Panics
		"/home/",    // File paths
		"/app/",     // Container paths
		"sql:",      // SQL errors
		"pq:",       // PostgreSQL errors
		"connection refused",
		"no such host",
		"context deadline exceeded",
	}

	lowerMsg := strings.ToLower(msg)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerMsg, strings.ToLower(pattern)) {
			return fallback
		}
	}

	if len(msg) > 200 {
		return fallback
	}

	if strings.HasPrefix(msg, "blocked:") {
		return msg
	}

	if !strings.Contains(msg, "(status") && !strings.Contains(msg, "respBody") {
		return msg
	}

	return fallback
}
