package validation

import (
	"strings"
)

// SanitizeErrorForUI returns a safe error message for display in the web UI.
// It prevents leaking internal API response details, database errors, or stack traces.
//
// The function extracts meaningful user-facing messages while hiding implementation details.
func SanitizeErrorForUI(err error, fallback string) string {
	if err == nil {
		return fallback
	}

	msg := err.Error()

	// If the error contains raw JSON (API response body), don't expose it
	if strings.Contains(msg, `{"`) || strings.Contains(msg, `{\"`) {
		return fallback
	}

	// If error contains stack traces or internal paths, don't expose it
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

	// If the error message is too long, it's probably not user-friendly
	if len(msg) > 200 {
		return fallback
	}

	// Check if it looks like a user-friendly message (short, no technical jargon)
	// Allow messages that seem to come from our API (which are already sanitized)
	if strings.HasPrefix(msg, "blocked:") {
		// This is from our own validation - safe to show
		return msg
	}

	// For short, simple error messages, allow them through
	// These are likely from our sanitized API responses
	if !strings.Contains(msg, "(status") && !strings.Contains(msg, "respBody") {
		return msg
	}

	return fallback
}
