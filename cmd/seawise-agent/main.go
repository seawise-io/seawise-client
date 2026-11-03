// Command seawise-agent runs the client v2 runtime. It keeps its state in
// <datadir>/v2 and reads existing client files without modifying them.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/enrol"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/paths"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
	"github.com/seawise/client/internal/updatecheck"
	"github.com/seawise/client/internal/visitor"
)

const usage = `seawise-agent: next version of the SeaWise client (in development).

The :latest and :1.x images run "seawise serve"; this agent is published
only as :2, :2.x.y, :beta and :stable. The target policy, forwarder,
HTTPS admin UI and first-run window described in cmd/seawise-agent/README.md
apply only to seawise-agent.

Configuration is through environment variables; see that README.
`

func main() {
	for _, a := range os.Args[1:] {
		if a == "-h" || a == "--help" || a == "help" {
			fmt.Print(usage)
			return
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	applyMemoryLimit(os.Getenv)

	st, err := store.Open(paths.DataDir(), time.Now)
	if err != nil {
		log.Error("open state", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	accessLog, err := accesslog.Open(accesslog.Config{Dir: st.Dir(), Logger: log})
	if err != nil {
		log.Error("open access log", "error", err)
		os.Exit(1)
	}
	defer accessLog.Close()

	if v := os.Getenv("SEAWISE_NAT64_PREFIXES"); v != "" {
		var prefixes []netip.Prefix
		for _, f := range strings.Split(v, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(f))
			if err != nil {
				log.Error("invalid SEAWISE_NAT64_PREFIXES", "value", f)
				os.Exit(1)
			}
			prefixes = append(prefixes, p)
		}
		if err := targetpolicy.SetNAT64Prefixes(prefixes); err != nil {
			log.Error("invalid SEAWISE_NAT64_PREFIXES", "error", err)
			os.Exit(1)
		}
	}

	keys, err := identity.Open(identity.BackendFile, st.Dir(), time.Now)
	if err != nil {
		log.Warn("device keystore unavailable; the tunnel waits", "error", err)
		keys = nil
	} else {
		defer keys.Close()
	}
	tr := startTrust(log, st)
	clock := session.OpenSignedClock(st.Dir(), log)
	call, err := deviceCaller(clock.Now)
	if err != nil {
		log.Error("device API client", "error", err)
		os.Exit(1)
	}
	var a *agent.Agent
	var ins *instructions
	_, dataStreams, err := newDataStreams(dataStreamSetup{
		log: log, st: st, keySet: tr.current, clock: clock, record: accessLog.Record,
		mode: func() visitor.Mode {
			if ins == nil {
				return visitor.Observe
			}
			return ins.visitorMode()
		},
		dial: func(ctx context.Context, localID string) (*forwarder.Upstream, error) { return a.Dial(ctx, localID) },
	})
	if err != nil {
		log.Error("data streams", "error", err)
		os.Exit(1)
	}
	cfg := agent.Config{
		Store:    st,
		Logger:   log,
		Gateways: targetpolicy.Gateways(),
		Tunnel: tunnelFactory(tunnelSetup{
			log: log, st: st, keys: keys, keySet: tr.current, keySetHold: tr.hold, name: envOr("SEAWISE_TUNNEL_NAME", defaultTunnelName),
			caller: call, clock: clock, streams: dataStreams.Serve,
		}),
	}
	cfg.Forward.Record = accessLog.Record
	a, err = agent.New(cfg)
	if err != nil {
		log.Error("start agent", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cp, err := controlplane.New(controlplane.Config{
		BaseURL: apiURL(st),
		// No 1.x call carries the token once the device key is enrolled or the token was refused.
		Token: func() string {
			if !enrol.LegacyAllowed(st.State()) {
				return ""
			}
			return st.Secrets().FRPToken
		},
		Version: constants.Version,
	})
	if err != nil {
		log.Error("control plane", "error", err)
		os.Exit(1)
	}
	// Held by enrolment while an enroll is in flight, by 1.x calls while
	// they use the token.
	legacyGate := &sync.RWMutex{}
	enrolment := startEnrolment(ctx, log, st, keys, call, a, legacyGate)
	pairing := startPairing(ctx, log, st, keys, call, a)
	apps, appsActive, appEngine := startAppSync(ctx, log, st, keys, call, a)
	startHealthProbe(ctx, log, st, cfg.Gateways, tunnelUp(ctx, a), appEngine)
	syncer, err := controlplane.NewSyncer(controlplane.SyncerConfig{Client: cp, Store: st, Agent: a, Version: constants.Version, Logger: log, SkipList: appsActive,
		Legacy: func() bool { return enrol.LegacyAllowed(st.State()) }, Gate: legacyGate})
	if err != nil {
		log.Error("control plane", "error", err)
		os.Exit(1)
	}
	syncDone := make(chan struct{})
	go func() { _ = syncer.Run(ctx); close(syncDone) }()

	updates, fresh := startUpdateCheck(ctx, log, st, tr)
	ins = newInstructions(log, st, tr, fresh, a.Reconcile)

	ui, err := startAdminUI(ctx, log, st, a, appEngine, accessLog, pairing, func(ctx context.Context) any {
		as, _ := a.Status(ctx)
		return map[string]any{"agent": as, "enrolment": enrolment(), "control_plane": syncer.Status(), "app_sync": apps(), "access_log": accessLog.Status(), "updates": updates(), "keyset": tr.status(), "instructions": ins.status(), "visitor_tokens": ins.visitorStatus(), "data_streams": dataStreams.Status()}
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
	// The syncer's offline call on stop is bounded by its OfflineTimeout.
	<-syncDone
}

// testUpdateConfig lets the memory budget test point update checks at a
// local test repository; it does nothing in release builds.
var testUpdateConfig = func(*updatecheck.Config) {}

// startUpdateCheck starts the signed update check and returns its status
// and whether its metadata is fresh. It hands each verified key set and
// floor to tr and shows release notices unless SEAWISE_UPDATE_CHECK=0; it
// never changes the running client.
func startUpdateCheck(ctx context.Context, log *slog.Logger, st *store.Store, tr *trust) (func() updatecheck.Status, func(time.Time) bool) {
	never := func(time.Time) bool { return false }
	fixed := func(s updatecheck.Status) (func() updatecheck.Status, func(time.Time) bool) {
		return func() updatecheck.Status { return s }, never
	}
	root, url := updatecheck.Pinned()
	cfg := updatecheck.Config{
		Root: root, URL: url, Dir: filepath.Join(st.Dir(), "tuf"),
		Channel: envOr("SEAWISE_UPDATE_CHANNEL", "stable"), Version: constants.Version, Logger: log,
		OnKeySet: tr.offer, AcceptedKeySet: tr.accepted, FloorBackup: tr.tufFloor, OnVerified: tr.setTUFFloor,
		HideNotices: os.Getenv("SEAWISE_UPDATE_CHECK") == "0",
	}
	testUpdateConfig(&cfg)
	c, err := updatecheck.New(cfg)
	if errors.Is(err, updatecheck.ErrNotConfigured) {
		log.Info("update checks are not configured in this build")
		return fixed(updatecheck.Status{State: updatecheck.StateNotConfigured})
	}
	if err != nil {
		log.Warn("update checks off", "error", err)
		return fixed(updatecheck.Status{State: updatecheck.StateError, Error: "update checks are off: " + err.Error()})
	}
	go c.Run(ctx)
	return c.Status, c.Fresh
}

// startAdminUI serves the admin UI on the admin port (plain HTTP, or HTTPS
// with SEAWISE_TLS=auto) and returns a function that waits for it to stop.
func startAdminUI(ctx context.Context, log *slog.Logger, st *store.Store, a *agent.Agent, apps *appsync.Engine, al *accesslog.Log, pairing adminui.Pairing, status func(context.Context) any) (func(), error) {
	auth, err := adminui.NewAuth(adminui.AuthConfig{Store: st, Logger: log})
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	extra := adminui.AllowedHostsFromEnv()
	useTLS := os.Getenv("SEAWISE_TLS") == "auto"
	var cert *adminui.CertInfo
	if useTLS {
		names, ips := adminui.LocalNames(hostname, extra)
		if cert, err = adminui.EnsureCert(st.Dir(), names, ips, time.Now()); err != nil {
			return nil, err
		}
	}
	port := constants.DefaultWebPort
	if v := os.Getenv("SEAWISE_PORT"); v != "" {
		if port, err = strconv.Atoi(v); err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid SEAWISE_PORT")
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
	cfg := adminui.Config{
		Store: st, Auth: auth, Status: status, AllowedHosts: extra, Hostname: hostname, Logger: log, TLS: useTLS,
		OnTargetsChanged: func(ctx context.Context) { _ = a.Reconcile(ctx) },
		AccessLog:        al,
		KillSwitch:       a.SetKillSwitch,
		Pairing:          pairing,
	}
	if apps != nil {
		cfg.Apps = apps
	}
	srv, err := adminui.New(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	var tlsCert *tls.Certificate
	if cert != nil {
		tlsCert = &cert.Cert
		log.Info("admin UI listening", "address", ln.Addr().String(), "https", true, "cert_sha256", cert.Fingerprint, "cert_new", cert.Regenerated)
	} else {
		log.Info("admin UI listening", "address", ln.Addr().String(), "https", false)
	}
	if auth.SetupRequired() {
		log.Warn("No password set. Open the admin UI and set one within "+adminui.FirstRunWindowText()+".", "port", port)
		t := time.AfterFunc(time.Until(auth.SetupDeadline()), func() {
			if auth.SetupRequired() {
				log.Warn("Setup window closed. Restart the client to set a password.")
			}
		})
		context.AfterFunc(ctx, func() { t.Stop() })
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx, ln, tlsCert); err != nil && !errors.Is(err, context.Canceled) {
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
