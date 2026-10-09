// Package agent runs the client v2 reconcile loop. One goroutine owns the
// frpc process and its config; everything else sends it intents.
package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/netproxy"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

const (
	DefaultBackoffBase  = time.Second
	DefaultBackoffMax   = 30 * time.Second
	DefaultStableAfter  = time.Minute
	DefaultStopTimeout  = 5 * time.Second
	DefaultPollInterval = 10 * time.Second
	DefaultTrustedCA    = "/etc/ssl/certs/ca-certificates.crt"
	ConfigFile          = "frpc.toml"
	PIDFile             = "frpc.pid"
	// EdgeCacheTTL bounds how old a cached frps address may be when local
	// DNS fails.
	EdgeCacheTTL       = 7 * 24 * time.Hour
	DefaultEdgeRecheck = 5 * time.Minute
	edgeResolveTimeout = 3 * time.Second
	edgeCacheRefresh   = time.Hour
	maxEdgeAddrs       = 4
)

// Proxy schemes frpc supports for its connection to frps.
var frpcProxySchemes = []string{"http", "socks5", "ntlm"}

var ErrStopped = errors.New("agent stopped")

type Config struct {
	Store    *store.Store
	FRPCPath string
	// AdminPort fixes frpc's loopback admin port; 0 picks a free port on
	// every start.
	AdminPort      int
	AllowedDomains []string
	TrustedCAFile  string
	BackoffBase    time.Duration
	BackoffMax     time.Duration
	StableAfter    time.Duration
	StopTimeout    time.Duration
	PollInterval   time.Duration
	After          func(time.Duration) <-chan time.Time
	Logger         *slog.Logger
	// Env is the frpc environment; nil gives frpc an empty one. Proxy
	// settings reach frpc through its config, never its environment.
	Env []string
	// Getenv supplies the proxy variables; nil reads the process
	// environment.
	Getenv netproxy.Getenv
	// ResolveEdge resolves the frps host before each frpc start; nil uses
	// the system resolver.
	ResolveEdge func(ctx context.Context, host string) ([]netip.Addr, error)
	// EdgeRecheck is how often DNS is tried again while frpc runs on a
	// cached address.
	EdgeRecheck time.Duration
	// Gateways are this host's default gateways, for the target policy.
	Gateways []netip.Addr
	// Forward configures the loopback forwarder frpc connects through.
	Forward forwarder.Config
}

// RefusedApp is an app the agent does not tunnel, with the reason.
type RefusedApp struct {
	LocalID string `json:"local_id"`
	Reason  string `json:"reason"`
}

type Status struct {
	Running      bool
	PID          int
	Paused       bool
	Holds        []string
	Restarts     int
	NextRestart  time.Duration
	LastExit     string
	LastError    string
	ConfigSHA256 string
	Proxies      []ProxyStatus
	PollError    string
	Refused      []RefusedApp
	// EdgeFallback is the cached frps address in use because DNS failed.
	EdgeFallback string
	Proxied      bool
}

type intentKind int

const (
	intentReconcile intentKind = iota
	intentHold
	intentRelease
	intentStatus
)

// Hold reasons. Tunnels run only while no hold is set.
const (
	HoldUser    = "user"
	HoldRemoval = "removal"
	// HoldKillSwitch is kept in the store, so it survives restarts.
	HoldKillSwitch = store.HoldKillSwitch
)

type intent struct {
	kind   intentKind
	reason string
	reply  chan reply
}

type reply struct {
	status Status
	err    error
}

type exitEvent struct {
	pid int
	err error
}

type pollEvent struct {
	pid     int
	proxies []ProxyStatus
	err     error
}

type process struct {
	cmd      *exec.Cmd
	pid      int
	started  time.Time
	stopping bool
	done     chan struct{}
}

type Agent struct {
	cfg     Config
	log     *slog.Logger
	intents chan intent
	exits   chan exitEvent
	polls   chan pollEvent
	done    chan struct{}

	// Owned by the loop goroutine.
	proc          *process
	admin         *adminClient
	adminPort     int
	holds         map[string]bool
	fwd           *forwarder.Forwarder
	crashes       int
	restartAt     <-chan time.Time
	writtenCommon string
	writtenProxy  string
	adminUser     string
	adminPass     string
	connectionID  string
	status        Status
	polling       bool
	runCtx        context.Context
	// edgeDial is the cached address frpc dials instead of edgeHost.
	edgeHost string
	edgeDial string
}

func New(cfg Config) (*Agent, error) {
	if cfg.Store == nil {
		return nil, errors.New("store required")
	}
	if cfg.FRPCPath == "" {
		return nil, errors.New("frpc path required")
	}
	if cfg.AllowedDomains == nil {
		cfg.AllowedDomains = constants.AllowedFRPDomains
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = DefaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.StableAfter <= 0 {
		cfg.StableAfter = DefaultStableAfter
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = DefaultStopTimeout
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.ResolveEdge == nil {
		cfg.ResolveEdge = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if cfg.EdgeRecheck <= 0 {
		cfg.EdgeRecheck = DefaultEdgeRecheck
	}
	user, err := randomHex(8)
	if err != nil {
		return nil, err
	}
	pass, err := randomHex(24)
	if err != nil {
		return nil, err
	}
	connID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	fwdCfg := cfg.Forward
	fwdCfg.Gateways = cfg.Gateways
	if fwdCfg.Logger == nil {
		fwdCfg.Logger = cfg.Logger
	}
	return &Agent{
		cfg:          cfg,
		log:          cfg.Logger.With("component", "agent"),
		intents:      make(chan intent),
		exits:        make(chan exitEvent, 4),
		polls:        make(chan pollEvent, 1),
		done:         make(chan struct{}),
		adminUser:    user,
		adminPass:    pass,
		connectionID: connID,
		holds:        map[string]bool{},
		fwd:          forwarder.New(fwdCfg),
	}, nil
}

func (a *Agent) ConfigPath() string {
	return filepath.Join(a.cfg.Store.Dir(), ConfigFile)
}

// Run owns frpc until ctx is cancelled, then stops it.
func (a *Agent) Run(ctx context.Context) error {
	defer close(a.done)
	// Children get Pdeathsig tied to the thread that forks them, so every
	// start must come from this one locked thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	a.runCtx = ctx
	a.killStale()
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	recheck := time.NewTicker(a.cfg.EdgeRecheck)
	defer recheck.Stop()

	a.reconcile()
	for {
		select {
		case <-ctx.Done():
			a.stopProcess()
			a.fwd.Close()
			return ctx.Err()
		case in := <-a.intents:
			in.reply <- a.handle(in)
		case ev := <-a.exits:
			a.onExit(ev)
		case <-a.restartAt:
			a.restartAt = nil
			a.status.NextRestart = 0
			a.reconcile()
		case <-ticker.C:
			if (a.proc != nil || a.writtenCommon != "") && a.cfg.Store.State().HasHold(HoldKillSwitch) {
				a.reconcile()
			}
			a.startPoll()
		case <-recheck.C:
			a.recheckEdge()
		case pe := <-a.polls:
			a.polling = false
			if a.proc != nil && pe.pid == a.proc.pid {
				a.status.Proxies = pe.proxies
				a.status.PollError = ""
				if pe.err != nil {
					a.status.PollError = pe.err.Error()
				}
			}
		}
	}
}

// ConnectionID identifies this agent run to the control plane.
func (a *Agent) ConnectionID() string { return a.connectionID }

func (a *Agent) Reconcile(ctx context.Context) error {
	_, err := a.send(ctx, intentReconcile, "")
	return err
}

func (a *Agent) Pause(ctx context.Context) error { return a.Hold(ctx, HoldUser) }

func (a *Agent) Resume(ctx context.Context) error { return a.Release(ctx, HoldUser) }

// ErrKillSwitchReason is returned when Hold or Release is called with the
// kill switch reason; only SetKillSwitch changes it.
var ErrKillSwitchReason = errors.New("the kill switch is changed only through SetKillSwitch")

// Hold stops tunnels until every hold is released.
func (a *Agent) Hold(ctx context.Context, reason string) error {
	if reason == HoldKillSwitch {
		return ErrKillSwitchReason
	}
	_, err := a.send(ctx, intentHold, reason)
	return err
}

func (a *Agent) Release(ctx context.Context, reason string) error {
	if reason == HoldKillSwitch {
		return ErrKillSwitchReason
	}
	_, err := a.send(ctx, intentRelease, reason)
	return err
}

// SetKillSwitch drops or restores every tunnel. The persisted hold is what
// the loop obeys, on every reconcile. If the store cannot be written when
// turning it on, the hold is still applied in memory; turning it off needs
// the store first, so a restart cannot bring tunnels back unasked. The
// change is delivered to the loop even if ctx ends first.
func (a *Agent) SetKillSwitch(ctx context.Context, on bool) error {
	err := a.cfg.Store.Update(func(st *store.State) error {
		st.Holds = slices.DeleteFunc(st.Holds, func(h string) bool { return h == HoldKillSwitch })
		if on {
			st.Holds = append(st.Holds, HoldKillSwitch)
		}
		return nil
	})
	persisted := err == nil || errors.Is(err, store.ErrNotDurable)
	if !persisted && !on {
		return fmt.Errorf("persist kill switch: %w", err)
	}
	kind := intentRelease
	if on {
		kind = intentHold
		a.log.Warn("kill switch on: all tunnels dropped")
	} else {
		a.log.Info("kill switch off")
	}
	_, serr := a.send(context.WithoutCancel(ctx), kind, HoldKillSwitch)
	if !persisted {
		return errors.Join(fmt.Errorf("persist kill switch: %w", err), serr)
	}
	return serr
}

func (a *Agent) Status(ctx context.Context) (Status, error) {
	return a.send(ctx, intentStatus, "")
}

func (a *Agent) send(ctx context.Context, kind intentKind, reason string) (Status, error) {
	if (kind == intentHold || kind == intentRelease) && reason == "" {
		return Status{}, errors.New("hold reason required")
	}
	r := make(chan reply, 1)
	select {
	case a.intents <- intent{kind: kind, reason: reason, reply: r}:
	case <-ctx.Done():
		return Status{}, ctx.Err()
	case <-a.done:
		return Status{}, ErrStopped
	}
	select {
	case rep := <-r:
		return rep.status, rep.err
	case <-ctx.Done():
		return Status{}, ctx.Err()
	}
}

func (a *Agent) handle(in intent) reply {
	var err error
	switch in.kind {
	case intentReconcile:
		err = a.reconcile()
	case intentHold:
		a.holds[in.reason] = true
		err = a.reconcile()
	case intentRelease:
		delete(a.holds, in.reason)
		err = a.reconcile()
	}
	return reply{status: a.snapshot(), err: err}
}

// currentHolds merges in-memory holds with the ones persisted in the
// store, so the two cannot diverge.
func (a *Agent) currentHolds() []string {
	out := make([]string, 0, len(a.holds)+1)
	for h := range a.holds {
		out = append(out, h)
	}
	for _, h := range a.cfg.Store.State().Holds {
		if !a.holds[h] {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func (a *Agent) snapshot() Status {
	s := a.status
	s.EdgeFallback = a.edgeDial
	s.Holds = a.currentHolds()
	s.Paused = len(s.Holds) > 0
	s.Proxies = append([]ProxyStatus(nil), a.status.Proxies...)
	s.Refused = append([]RefusedApp(nil), a.status.Refused...)
	if a.proc != nil {
		s.Running, s.PID = true, a.proc.pid
	}
	return s
}

func (a *Agent) desired() (*desired, error) {
	if len(a.currentHolds()) > 0 {
		return nil, nil
	}
	st := a.cfg.Store.State()
	sec := a.cfg.Store.Secrets()
	if st.Account == nil {
		return nil, nil
	}
	if sec.FRPToken == "" {
		return nil, fmt.Errorf("%w: paired account has no frp token", store.ErrInvalid)
	}
	acc := st.Account
	if !allowedServer(acc.FRPServerAddr, a.cfg.AllowedDomains) {
		return nil, fmt.Errorf("frp server %q is not an allowed domain", acc.FRPServerAddr)
	}
	if acc.FRPServerPort < 1 || acc.FRPServerPort > 65535 {
		return nil, fmt.Errorf("frp server port %d out of range", acc.FRPServerPort)
	}
	// The token is sent at login, so the connection is always TLS with a
	// verified certificate, whatever the imported v1 setting was.
	if !fileExists(a.cfg.TrustedCAFile) {
		return nil, fmt.Errorf("CA bundle %q not found; refusing to connect to frps without certificate verification", a.cfg.TrustedCAFile)
	}
	proxyURL, err := a.frpcProxy(acc.FRPServerAddr, acc.FRPServerPort)
	if err != nil {
		return nil, err
	}
	a.status.Proxied = proxyURL != ""
	dial := acc.FRPServerAddr
	if proxyURL == "" && a.edgeHost == acc.FRPServerAddr && a.edgeDial != "" {
		dial = a.edgeDial
	}
	return &desired{
		serverAddr: dial, tlsName: acc.FRPServerAddr, serverPort: acc.FRPServerPort, proxyURL: proxyURL,
		token: sec.FRPToken, serverID: acc.ServerID, connectionID: a.connectionID,
		adminHost: "127.0.0.1", adminPort: a.adminPort, adminUser: a.adminUser, adminPass: a.adminPass,
		trustedCA: a.cfg.TrustedCAFile, proxies: a.proxies(st.Targets),
	}, nil
}

// frpcProxy returns the proxy URL frpc uses for frps, or "" for a direct
// connection. A proxy frpc cannot use is an error rather than a silent
// direct connection.
func (a *Agent) frpcProxy(host string, port int) (string, error) {
	u, err := netproxy.ForHost(a.cfg.Getenv, host, port, netproxy.Tunnel...)
	if err != nil {
		return "", fmt.Errorf("proxy settings: %w", err)
	}
	if u == nil {
		return "", nil
	}
	if err := netproxy.CheckScheme(u, frpcProxySchemes...); err != nil {
		return "", fmt.Errorf("proxy settings: %w (frpc supports http, socks5 and ntlm)", err)
	}
	return u.String(), nil
}

// resolveEdge runs before each frpc start without a proxy. A successful
// lookup is cached and frpc dials the host name; a failed one falls back
// to a cached address for the same host that is younger than
// EdgeCacheTTL. TLS still verifies the host name either way.
func (a *Agent) resolveEdge(d *desired) {
	host := d.tlsName
	ctx, cancel := context.WithTimeout(a.ctx(), edgeResolveTimeout)
	addrs, err := a.cfg.ResolveEdge(ctx, host)
	cancel()
	usable := usableEdgeAddrs(addrs)
	a.edgeHost, a.edgeDial, d.serverAddr = host, "", host
	if err == nil && len(usable) > 0 {
		a.cacheEdge(host, usable)
		return
	}
	e := a.cfg.Store.State().EdgeDNS
	if e == nil || e.Host != host || time.Since(e.ResolvedAt) >= EdgeCacheTTL {
		return
	}
	ip := e.Addrs[0]
	for _, s := range e.Addrs {
		if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
			ip = s
			break
		}
	}
	a.edgeDial, d.serverAddr = ip, ip
	a.log.Warn("DNS lookup for the tunnel server failed; using its last known address", "host", host, "addr", ip, "resolved_at", e.ResolvedAt)
}

func usableEdgeAddrs(addrs []netip.Addr) []string {
	var out []string
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.Zone() != "" || slices.Contains(out, a.String()) {
			continue
		}
		out = append(out, a.String())
		if len(out) == maxEdgeAddrs {
			break
		}
	}
	return out
}

func (a *Agent) cacheEdge(host string, addrs []string) {
	e := a.cfg.Store.State().EdgeDNS
	if e != nil && e.Host == host && slices.Equal(e.Addrs, addrs) && time.Since(e.ResolvedAt) < edgeCacheRefresh {
		return
	}
	err := a.cfg.Store.Update(func(st *store.State) error {
		st.EdgeDNS = &store.EdgeDNS{Host: host, Addrs: addrs, ResolvedAt: time.Now().UTC()}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotDurable) {
		a.log.Warn("store tunnel server address", "error", err)
	}
}

// recheckEdge moves frpc back to the host name once DNS works again.
func (a *Agent) recheckEdge() {
	if a.edgeDial == "" || a.proc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx(), edgeResolveTimeout)
	addrs, err := a.cfg.ResolveEdge(ctx, a.edgeHost)
	cancel()
	usable := usableEdgeAddrs(addrs)
	if err != nil || len(usable) == 0 {
		return
	}
	a.cacheEdge(a.edgeHost, usable)
	a.edgeDial = ""
	a.log.Info("DNS works again; reconnecting by host name", "host", a.edgeHost)
	_ = a.reconcile()
}

// proxies admits targets through the policy and routes each one through its
// loopback forwarder listener.
func (a *Agent) proxies(targets []store.Target) []proxyEntry {
	ok, refused := admit(targets, a.cfg.Gateways)
	a.status.Refused = refused
	apps := make([]forwarder.App, 0, len(ok))
	for _, t := range ok {
		apps = append(apps, forwarder.App{ID: t.LocalID, Host: t.Host, Port: t.Port, Rule: targetpolicy.RuleFor(t)})
	}
	ports := a.fwd.Sync(apps)
	out := make([]proxyEntry, 0, len(ok))
	for _, t := range ok {
		if p, found := ports[t.LocalID]; found {
			out = append(out, proxyEntry{name: t.Name, subdomain: t.Subdomain, port: p})
		}
	}
	return out
}

func (a *Agent) reconcile() error {
	d, err := a.desired()
	if err != nil {
		a.status.LastError = err.Error()
		a.dropAll()
		return err
	}
	if d == nil {
		a.dropAll()
		return nil
	}
	if a.proc == nil {
		if a.restartAt != nil {
			return nil
		}
		return a.startProcess(d)
	}
	commonChanged, proxiesChanged, err := a.writeConfig(d)
	if err != nil {
		return err
	}
	switch {
	case commonChanged:
		a.stopProcess()
		return a.startProcess(d)
	case proxiesChanged:
		ctx, cancel := context.WithTimeout(a.ctx(), 3*time.Second)
		defer cancel()
		if err := a.admin.reload(ctx); err != nil {
			a.log.Warn("frpc reload failed, restarting", "error", err)
			a.stopProcess()
			return a.startProcess(d)
		}
	}
	return nil
}

// dropAll closes every forwarder listener and connection first, so no
// visitor gets through while frpc stops, then stops frpc and removes
// frpc.toml so no proxy list is left on disk.
func (a *Agent) dropAll() {
	a.fwd.Sync(nil)
	a.stopProcess()
	if err := os.Remove(a.ConfigPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.log.Warn("remove frpc config", "error", err)
	}
	a.writtenCommon, a.writtenProxy, a.status.ConfigSHA256 = "", "", ""
}

func (a *Agent) writeConfig(d *desired) (commonChanged, proxiesChanged bool, err error) {
	common, proxies := d.renderCommon(), d.renderProxies()
	commonChanged = common != a.writtenCommon
	proxiesChanged = proxies != a.writtenProxy
	if commonChanged || proxiesChanged || !fileExists(a.ConfigPath()) {
		data := []byte(common + proxies)
		if err := store.WriteFileAtomic(a.ConfigPath(), data, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
			a.status.LastError = err.Error()
			return false, false, err
		}
		a.writtenCommon, a.writtenProxy = common, proxies
		sum := sha256.Sum256(data)
		a.status.ConfigSHA256 = hex.EncodeToString(sum[:])
	}
	return commonChanged, proxiesChanged, nil
}

func (a *Agent) ctx() context.Context {
	if a.runCtx != nil {
		return a.runCtx
	}
	return context.Background()
}

func (a *Agent) startProcess(d *desired) error {
	port := a.cfg.AdminPort
	if port == 0 {
		var err error
		if port, err = freeLoopbackPort(); err != nil {
			a.status.LastError = err.Error()
			a.scheduleRestart(time.Time{})
			return err
		}
	}
	admin, err := newAdminClient("127.0.0.1", port, a.adminUser, a.adminPass, 2*time.Second)
	if err != nil {
		return err
	}
	if d.proxyURL == "" {
		a.resolveEdge(d)
	}
	a.adminPort, a.admin, d.adminPort = port, admin, port
	if _, _, err := a.writeConfig(d); err != nil {
		a.scheduleRestart(time.Time{})
		return err
	}

	cmd := exec.Command(a.cfg.FRPCPath, "-c", a.ConfigPath())
	setPdeathsig(cmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = a.cfg.Env
	if cmd.Env == nil {
		cmd.Env = childEnv()
	}
	if err := cmd.Start(); err != nil {
		a.status.LastError = err.Error()
		a.scheduleRestart(time.Time{})
		return err
	}
	p := &process{cmd: cmd, pid: cmd.Process.Pid, started: time.Now(), done: make(chan struct{})}
	a.proc = p
	a.status.LastError = ""
	a.status.Proxies = nil
	a.log.Info("frpc started", "pid", p.pid)
	if err := a.recordPID(p.pid); err != nil {
		a.log.Warn("record frpc pid", "error", err)
	}
	go func() {
		err := cmd.Wait()
		close(p.done)
		select {
		case a.exits <- exitEvent{pid: p.pid, err: err}:
		case <-a.done:
		}
	}()
	return nil
}

func (a *Agent) stopProcess() {
	p := a.proc
	if p == nil {
		return
	}
	p.stopping = true
	a.proc = nil
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(a.cfg.StopTimeout):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	a.clearPID()
	a.log.Info("frpc stopped", "pid", p.pid)
}

func (a *Agent) onExit(ev exitEvent) {
	if a.proc == nil || ev.pid != a.proc.pid {
		return
	}
	p := a.proc
	a.proc = nil
	a.clearPID()
	a.status.Restarts++
	a.status.LastExit = fmt.Sprint(ev.err)
	a.log.Warn("frpc exited", "pid", ev.pid, "error", ev.err)
	a.scheduleRestart(p.started)
}

// scheduleRestart arms the backoff timer. started is the zero time when the
// process never came up.
func (a *Agent) scheduleRestart(started time.Time) {
	if !started.IsZero() && time.Since(started) >= a.cfg.StableAfter {
		a.crashes = 0
	}
	a.crashes++
	d := backoff(a.crashes, a.cfg.BackoffBase, a.cfg.BackoffMax)
	a.status.NextRestart = d
	a.restartAt = a.cfg.After(d)
}

func backoff(attempt int, base, max time.Duration) time.Duration {
	d := base
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}

func (a *Agent) startPoll() {
	if a.proc == nil || a.polling {
		return
	}
	a.polling = true
	pid, admin := a.proc.pid, a.admin
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		proxies, err := admin.status(ctx)
		select {
		case a.polls <- pollEvent{pid: pid, proxies: proxies, err: err}:
		case <-a.done:
		}
	}()
}

// frpc is a static binary given absolute paths, an explicit CA file and
// its proxy in the config, so it needs nothing from the environment.
func childEnv() []string { return []string{} }

func freeLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
