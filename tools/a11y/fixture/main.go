// Command fixture serves the agent's admin UI on loopback with sample
// data in every state the UI can show, for the accessibility check.
// A second UI, on its own port, shows the state after the first-run
// window closed without a password; a third is paired and can disconnect. It is a test tool and is not part of
// any release image.
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
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/pair"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/updatecheck"
)

func main() {
	dir := flag.String("dir", "", "empty data folder for the fixture")
	port := flag.Int("port", 0, "loopback port (0 picks one)")
	ready := flag.String("ready", "", "file that receives the three URLs once serving")
	pairing := flag.String("pair", pair.StateIdle, "starting pairing state: none, pending, paired or reconnect")
	flag.Parse()
	if *dir == "" || *ready == "" {
		fmt.Fprintln(os.Stderr, "usage: fixture -dir <folder> -ready <file> [-port n] [-pair state]")
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, *dir, *port, *ready, *pairing); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("fixture", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, dir string, port int, ready, pairing string) error {
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
		Store: st, Auth: auth, Logger: log, TLS: true,
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
		Pairing:   newFakePairing(pairing),
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
	closedURL, serveClosed, err := closedUI(ctx, log, filepath.Join(dir, "closed"), now)
	if err != nil {
		ln.Close()
		return err
	}
	go func() {
		if err := serveClosed(); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("fixture, closed setup UI", "error", err)
		}
	}()
	pairedURL, servePaired, err := pairedUI(ctx, log, filepath.Join(dir, "paired"), now)
	if err != nil {
		ln.Close()
		return err
	}
	go func() {
		if err := servePaired(); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("fixture, paired UI", "error", err)
		}
	}()
	info := fmt.Sprintf("https://%s/\n%s\n%s\n", ln.Addr(), closedURL, pairedURL)
	if err := os.WriteFile(ready, []byte(info), 0o600); err != nil {
		ln.Close()
		return err
	}
	return srv.Serve(ctx, ln, &cert.Cert)
}

// closedUI serves a UI with no password whose first-run window has passed.
func closedUI(ctx context.Context, log *slog.Logger, dir string, now time.Time) (string, func() error, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	st, err := store.Open(dir, time.Now)
	if err != nil {
		return "", nil, err
	}
	started := now.Add(-constants.FirstRunSetupWindow - time.Minute)
	var once sync.Once
	clock := func() time.Time {
		t := time.Now()
		once.Do(func() { t = started })
		return t
	}
	auth, err := adminui.NewAuth(adminui.AuthConfig{Store: st, Logger: log, BcryptCost: 4, Now: clock})
	if err != nil {
		st.Close()
		return "", nil, err
	}
	names, ips := adminui.LocalNames("", nil)
	cert, err := adminui.EnsureCert(st.Dir(), names, ips, now)
	if err != nil {
		st.Close()
		return "", nil, err
	}
	srv, err := adminui.New(adminui.Config{Store: st, Auth: auth, Logger: log, TLS: true, Status: func(context.Context) any { return map[string]any{} }})
	if err != nil {
		st.Close()
		return "", nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		st.Close()
		return "", nil, err
	}
	return "https://" + ln.Addr().String() + "/", func() error {
		defer st.Close()
		return srv.Serve(ctx, ln, &cert.Cert)
	}, nil
}

// pairedUI serves a paired UI whose disconnect returns it to unpaired.
func pairedUI(ctx context.Context, log *slog.Logger, dir string, now time.Time) (string, func() error, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	st, err := store.Open(dir, time.Now)
	if err != nil {
		return "", nil, err
	}
	fail := func(err error) (string, func() error, error) { st.Close(); return "", nil, err }
	if err := seed(st, now); err != nil {
		return fail(err)
	}
	auth, err := adminui.NewAuth(adminui.AuthConfig{Store: st, Logger: log, BcryptCost: 4})
	if err != nil {
		return fail(err)
	}
	names, ips := adminui.LocalNames("", nil)
	cert, err := adminui.EnsureCert(st.Dir(), names, ips, now)
	if err != nil {
		return fail(err)
	}
	p := newFakePairing(pair.StatePaired)
	srv, err := adminui.New(adminui.Config{
		Store: st, Auth: auth, Logger: log, TLS: true, Pairing: p,
		Status: func(context.Context) any { return status(now, false) },
		Disconnect: func(context.Context) (adminui.Disconnected, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.st.State != pair.StatePaired {
				return adminui.Disconnected{}, adminui.ErrNotPaired
			}
			p.st = pair.Status{State: pair.StateIdle}
			return adminui.Disconnected{Told: true}, nil
		},
	})
	if err != nil {
		return fail(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail(err)
	}
	return "https://" + ln.Addr().String() + "/", func() error {
		defer st.Close()
		return srv.Serve(ctx, ln, &cert.Cert)
	}, nil
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
			{LocalID: "notes", Name: "Notes", Host: "192.168.1.30", Port: 3000, Source: store.SourceLocal, ConfirmedAt: &confirmed, Disabled: true, RemovedFromAccount: true},
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

// fakePairing walks the pairing states without a network.
type fakePairing struct {
	mu sync.Mutex
	st pair.Status
}

func newFakePairing(state string) *fakePairing {
	f := &fakePairing{}
	switch state {
	case pair.StatePending:
		f.st = pendingStatus("Home server")
	case pair.StatePaired, pair.StateReconnect:
		f.st = pair.Status{State: state, ServerName: "Home server"}
	default:
		f.st = pair.Status{State: pair.StateIdle}
	}
	return f
}

func pendingStatus(name string) pair.Status {
	return pair.Status{
		State: pair.StatePending, Code: "WDJB-MJHT", ApproveURL: "https://seawise.io/connect",
		ExpiresAt: time.Now().Add(10 * time.Minute), KeyFingerprint: "SHA256:7f3a 91c2 0b4e d8a1", ServerName: name,
	}
}

func (f *fakePairing) Start(_ context.Context, name string) (pair.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.State == pair.StatePaired {
		return pair.Status{}, pair.ErrPaired
	}
	f.st = pendingStatus(name)
	return f.st, nil
}

func (f *fakePairing) Cancel() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.State == pair.StatePending {
		f.st = pair.Status{State: pair.StateIdle}
	}
}

func (f *fakePairing) Status() pair.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st
}
