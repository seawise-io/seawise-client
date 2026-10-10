package adminui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/seawise/client/internal/store"
)

// InContainer reports whether the agent runs in a container, where the UI
// must listen on all interfaces to be reachable through a published port.
// Signals: SEAWISE_CONTAINER=1 (explicit override), /.dockerenv (Docker),
// /run/.containerenv (Podman), or a container runtime in PID 1's cgroup
// (Docker, containerd, Kubernetes, Podman, LXC).
func InContainer() bool { return detectContainer("/", os.Getenv) }

func detectContainer(root string, getenv func(string) string) bool {
	if getenv("SEAWISE_CONTAINER") == "1" {
		return true
	}
	for _, p := range []string{".dockerenv", "run/.containerenv"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return true
		}
	}
	b, err := os.ReadFile(filepath.Join(root, "proc/1/cgroup")) // #nosec G304 -- fixed name under root, which is "/" outside tests
	if err != nil {
		return false
	}
	cg := string(b)
	for _, marker := range []string{"/docker", "/kubepods", "containerd", "libpod", "/lxc"} {
		if strings.Contains(cg, marker) {
			return true
		}
	}
	return false
}

// BindAddr picks the admin UI address. An explicit address always wins.
// Containers listen on all interfaces so a published port reaches the UI;
// everything else listens on loopback. An upgraded native install that
// used to listen on all interfaces gets a notice explaining how to keep
// LAN access. Setup always needs the one-time code.
func BindAddr(explicit string, st store.State, sec store.Secrets, container bool) (addr, notice string) {
	switch {
	case explicit != "":
		return explicit, ""
	case container:
		return "0.0.0.0", ""
	case st.UpgradedAt != nil && sec.AdminPasswordHash != "":
		return "127.0.0.1", "The admin UI now listens on 127.0.0.1 only. To reach it from other devices, set SEAWISE_BIND_ADDR=0.0.0.0 (or a LAN address) and restart."
	default:
		return "127.0.0.1", ""
	}
}
