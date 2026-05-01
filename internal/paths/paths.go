// Package paths provides the data directory path used by all components.
package paths

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// DataDir returns the data directory for SeaWise configuration and state.
// Checks SEAWISE_DATA_DIR env var first (set to /config in Docker).
// Falls back to ~/.seawise for native installs.
//
// SEA-155: previously fell back to /tmp/.seawise when no home dir was
// available. /tmp is world-readable on multi-user systems, so credentials
// (FRP token, password hash, session cookies) could leak. Now this calls
// os.Exit(1) with an actionable error instead — operators must set
// SEAWISE_DATA_DIR explicitly when running without a home dir.
func DataDir() string {
	if dir := os.Getenv("SEAWISE_DATA_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		slog.Error(
			"No home directory and SEAWISE_DATA_DIR not set — refusing to fall back to /tmp",
			"component", "paths",
			"hint", "Set SEAWISE_DATA_DIR to a directory only your user can read (e.g. /var/lib/seawise with 0700 perms).",
		)
		fmt.Fprintln(os.Stderr, "fatal: cannot determine data directory")
		os.Exit(1)
	}
	return filepath.Join(home, ".seawise")
}
