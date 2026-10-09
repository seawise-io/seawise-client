// Command seawise-agent runs the client v2 runtime. It keeps its state in
// <datadir>/v2 and reads existing client files without modifying them.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/paths"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	st, err := store.Open(paths.DataDir(), time.Now)
	if err != nil {
		log.Error("open state", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	cfg := agent.Config{
		Store:         st,
		FRPCPath:      envOr("SEAWISE_FRPC_PATH", "/app/frpc"),
		TrustedCAFile: envOr("SEAWISE_TRUSTED_CA_FILE", agent.DefaultTrustedCA),
		Logger:        log,
		Gateways:      targetpolicy.Gateways(),
	}
	if v := os.Getenv("SEAWISE_FRPC_ADMIN_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			log.Error("invalid SEAWISE_FRPC_ADMIN_PORT", "value", v)
			os.Exit(1)
		}
		cfg.AdminPort = p
	}
	a, err := agent.New(cfg)
	if err != nil {
		log.Error("start agent", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cp, err := controlplane.New(controlplane.Config{
		BaseURL: apiURL(st),
		Token:   func() string { return st.Secrets().FRPToken },
		Version: constants.Version,
	})
	if err != nil {
		log.Error("control plane", "error", err)
		os.Exit(1)
	}
	syncer, err := controlplane.NewSyncer(controlplane.SyncerConfig{Client: cp, Store: st, Agent: a, Version: constants.Version, Logger: log})
	if err != nil {
		log.Error("control plane", "error", err)
		os.Exit(1)
	}
	go func() { _ = syncer.Run(ctx) }()

	ui, err := startAdminUI(ctx, log, st, a, func(ctx context.Context) any {
		as, _ := a.Status(ctx)
		return map[string]any{"agent": as, "control_plane": syncer.Status()}
	})
	if err != nil {
		log.Error("admin UI", "error", err)
		os.Exit(1)
	}
	defer ui()

	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

// startAdminUI serves HTTPS and plain HTTP on the admin port and returns a
// function that waits for it to stop.
func startAdminUI(ctx context.Context, log *slog.Logger, st *store.Store, a *agent.Agent, status func(context.Context) any) (func(), error) {
	auth, err := adminui.NewAuth(adminui.AuthConfig{Store: st, PasswordFile: os.Getenv("SEAWISE_ADMIN_PASSWORD_FILE"), Logger: log})
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	extra := adminui.AllowedHostsFromEnv()
	names, ips := adminui.LocalNames(hostname, extra)
	cert, err := adminui.EnsureCert(st.Dir(), names, ips, time.Now())
	if err != nil {
		return nil, err
	}
	port := constants.DefaultWebPort
	if v := os.Getenv("SEAWISE_WEB_PORT"); v != "" {
		if port, err = strconv.Atoi(v); err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid SEAWISE_WEB_PORT")
		}
	}
	bind, notice := adminui.BindAddr(os.Getenv("SEAWISE_BIND_ADDR"), st.State(), st.Secrets(), adminui.InContainer())
	if notice != "" {
		log.Warn(notice)
		inner := status
		status = func(ctx context.Context) any {
			return map[string]any{"status": inner(ctx), "notices": []string{notice}}
		}
	}
	srv, err := adminui.New(adminui.Config{
		Store: st, Auth: auth, Status: status, AllowedHosts: extra, Hostname: hostname, Logger: log,
		PublicAllowed:    os.Getenv("SEAWISE_ALLOW_PUBLIC_TARGETS") == "1",
		OnTargetsChanged: func(ctx context.Context) { _ = a.Reconcile(ctx) },
	})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	log.Info("admin UI listening", "address", ln.Addr().String(), "https", true, "cert_sha256", cert.Fingerprint, "cert_new", cert.Regenerated)
	if auth.SetupRequired() {
		log.Warn("first run: open the admin UI over HTTPS and enter the setup code from the setup-code file",
			"file", auth.CodePath(), "port", port, "cert_sha256", cert.Fingerprint)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx, ln, cert.Cert); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("admin UI stopped", "error", err)
		}
	}()
	return func() { <-done }, nil
}

// apiURL keeps the v1 precedence: the origin stored at pairing wins.
func apiURL(st *store.Store) string {
	if a := st.State().Account; a != nil && a.APIURL != "" {
		return a.APIURL
	}
	return envOr("SEAWISE_API_URL", constants.DefaultAPIURL)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
