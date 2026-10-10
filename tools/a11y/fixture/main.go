// Command fixture serves the agent's admin UI on loopback with sample
// data in every state the UI can show, for the accessibility check. It is
// a test tool and is not part of any release image.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/updatecheck"
)

func main() {
	dir := flag.String("dir", "", "empty data folder for the fixture")
	port := flag.Int("port", 0, "loopback port (0 picks one)")
	ready := flag.String("ready", "", "file that receives the URL and setup code path once serving")
	flag.Parse()
	if *dir == "" || *ready == "" {
		fmt.Fprintln(os.Stderr, "usage: fixture -dir <folder> -ready <file> [-port n]")
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, *dir, *port, *ready); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("fixture", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, dir string, port int, ready string) error {
	now := time.Now()
	st, err := store.Open(dir, time.Now)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := seed(st, now); err != nil {
		return err
	}
	al, err := accesslog.Open(accesslog.Config{Dir: st.Dir(), Logger: log})
	if err != nil {
		return err
	}
	defer al.Close()
	for i, r := range []string{"ok", "ok", "refused", "error"} {
		al.Record(accesslog.Entry{
			Time: now.Add(-time.Duration(i) * time.Minute), App: "media", Peer: "203.0.113." + strconv.Itoa(10+i) + ":51234",
			Target: "192.168.1.20:8096", BytesIn: int64(1200 * (i + 1)), BytesOut: int64(48000 * (i + 1)), DurationMS: int64(350 * (i + 1)), Result: r,
		})
	}
	al.Flush()

	auth, err := adminui.NewAuth(adminui.AuthConfig{Store: st, Logger: log, BcryptCost: 4})
	if err != nil {
		return err
	}
	names, ips := adminui.LocalNames("", nil)
	cert, err := adminui.EnsureCert(st.Dir(), names, ips, now)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	killed := false
	srv, err := adminui.New(adminui.Config{
		Store: st, Auth: auth, Logger: log,
		Status: func(context.Context) any {
			mu.Lock()
			defer mu.Unlock()
			return status(now, killed)
		},
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("no lookups in the fixture")
		},
		Gateways:  func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.1")} },
		AccessLog: al,
		KillSwitch: func(_ context.Context, on bool) error {
			mu.Lock()
			defer mu.Unlock()
			killed = on
			return nil
		},
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	info := fmt.Sprintf("https://%s/\n%s\n", ln.Addr(), auth.CodePath())
	if err := os.WriteFile(ready, []byte(info), 0o600); err != nil {
		ln.Close()
		return err
	}
	return srv.Serve(ctx, ln, cert.Cert)
}

func seed(st *store.Store, now time.Time) error {
	yes := true
	confirmed := now.Add(-24 * time.Hour)
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "fixture-token"; return nil }); err != nil {
		return err
	}
	return st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: "11111111-2222-4333-8444-555555555555", FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000}
		s.Targets = []store.Target{
			{LocalID: "media", Name: "Media server", Host: "192.168.1.20", Port: 8096, Subdomain: "media", Source: store.SourceLocal, Grandfathered: true},
			{LocalID: "router", Name: "Router", Host: "192.168.1.1", Port: 80, Subdomain: "router", Source: store.SourceLocal, ConfirmedAt: &confirmed},
			{LocalID: "docker", Name: "Docker API", Host: "127.0.0.1", Port: 2375, Subdomain: "docker", Source: store.SourceLocal, Grandfathered: true},
			{LocalID: "notes", Name: "Notes", Host: "192.168.1.30", Port: 3000, Subdomain: "notes", Source: store.SourceLocal, ConfirmedAt: &confirmed, Disabled: true},
			{LocalID: "photos", Name: "Photos", Host: "192.168.1.31", Port: 2342, Subdomain: "photos", Source: store.SourceLocal, ConfirmedAt: &confirmed, ServerDisableRequestedAt: &now},
			{LocalID: "wiki", Name: "Wiki", Host: "192.168.1.32", Port: 8080, Subdomain: "wiki", Source: store.SourceLocal, ConfirmedAt: &confirmed, ServerPublic: true},
			{LocalID: "unnamed", Host: "192.168.1.34", Port: 8443, Subdomain: "unnamed", Source: store.SourceLocal, Grandfathered: true},
			{LocalID: "blog", Name: "Blog", Host: "192.168.1.33", Port: 2368, Subdomain: "blog", Source: store.SourceLocal, ConfirmedAt: &confirmed, Public: &yes, ServerPublic: true},
		}
		return nil
	})
}

func status(now time.Time, killed bool) any {
	holds := []string{}
	if killed {
		holds = append(holds, store.HoldKillSwitch)
	}
	checked := now.Add(-time.Hour)
	return map[string]any{
		"agent": map[string]any{"Running": !killed, "Holds": holds, "Restarts": 0, "Proxied": false},
		"control_plane": map[string]any{
			"last_heartbeat": now.Add(-20 * time.Second).UTC().Format(time.RFC3339), "state": "connected",
		},
		"updates": updatecheck.Status{
			State: "ok", Channel: "stable", Current: "2.0.0", CheckedAt: &checked, Fresh: true,
			Available: &updatecheck.Release{Channel: "stable", Version: "2.0.1", Ref: "ghcr.io/seawise-io/seawise-client@sha256:" + fmt.Sprintf("%064d", 0)},
		},
	}
}
