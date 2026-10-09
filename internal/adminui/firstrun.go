package adminui

import (
	"os"

	"github.com/seawise/client/internal/store"
)

// InContainer reports whether the agent runs in a container, where the UI
// must listen on all interfaces to be reachable through a published port.
func InContainer() bool {
	if os.Getenv("SEAWISE_CONTAINER") == "1" {
		return true
	}
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// BindAddr picks the admin UI address. An explicit address always wins. An
// upgraded install that already had a password keeps the previous default
// of all interfaces. New installs listen on loopback, except in a container;
// either way setup needs the one-time code.
func BindAddr(explicit string, st store.State, sec store.Secrets, container bool) string {
	switch {
	case explicit != "":
		return explicit
	case st.UpgradedAt != nil && sec.AdminPasswordHash != "":
		return "0.0.0.0"
	case container:
		return "0.0.0.0"
	default:
		return "127.0.0.1"
	}
}
