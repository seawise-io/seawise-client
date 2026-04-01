// Package paths provides the data directory path used by all components.
package paths

import (
	"os"
	"path/filepath"
)

// DataDir returns the data directory for SeaWise configuration and state.
// Checks SEAWISE_DATA_DIR env var first (set to /config in Docker).
// Falls back to ~/.seawise for native installs.
func DataDir() string {
	if dir := os.Getenv("SEAWISE_DATA_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/tmp"
	}
	return filepath.Join(home, ".seawise")
}
