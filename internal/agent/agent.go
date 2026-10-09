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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
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
)

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
	// Env is the frpc environment; nil passes only the proxy variables of
	// the current process.
	Env []string
}

type Status struct {
	Running      bool
	PID          int
	Paused       bool
	Restarts     int
	NextRestart  time.Duration
	LastExit     string
	LastError    string
	ConfigSHA256 string
	Proxies      []ProxyStatus
	PollError    string
}

type intentKind int

const (
	intentReconcile intentKind = iota
	intentPause
	intentResume
	intentStatus
)

type intent struct {
	kind  intentKind
	reply chan reply
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
	paused        bool
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

	a.reconcile()
	for {
		select {
		case <-ctx.Done():
			a.stopProcess()
			return ctx.Err()
		case in := <-a.intents:
			in.reply <- a.handle(in.kind)
		case ev := <-a.exits:
			a.onExit(ev)
		case <-a.restartAt:
			a.restartAt = nil
			a.status.NextRestart = 0
			a.reconcile()
		case <-ticker.C:
			a.startPoll()
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

func (a *Agent) Reconcile(ctx context.Context) error {
	_, err := a.send(ctx, intentReconcile)
	return err
}

func (a *Agent) Pause(ctx context.Context) error {
	_, err := a.send(ctx, intentPause)
	return err
}

func (a *Agent) Resume(ctx context.Context) error {
	_, err := a.send(ctx, intentResume)
	return err
}

func (a *Agent) Status(ctx context.Context) (Status, error) {
	return a.send(ctx, intentStatus)
}

func (a *Agent) send(ctx context.Context, kind intentKind) (Status, error) {
	r := make(chan reply, 1)
	select {
	case a.intents <- intent{kind: kind, reply: r}:
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

func (a *Agent) handle(kind intentKind) reply {
	var err error
	switch kind {
	case intentReconcile:
		err = a.reconcile()
	case intentPause:
		a.paused = true
		err = a.reconcile()
	case intentResume:
		a.paused = false
		err = a.reconcile()
	}
	return reply{status: a.snapshot(), err: err}
}

func (a *Agent) snapshot() Status {
	s := a.status
	s.Paused = a.paused
	s.Proxies = append([]ProxyStatus(nil), a.status.Proxies...)
	if a.proc != nil {
		s.Running, s.PID = true, a.proc.pid
	}
	return s
}

func (a *Agent) desired() (*desired, error) {
	if a.paused {
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
	return &desired{
		serverAddr: acc.FRPServerAddr, serverPort: acc.FRPServerPort,
		token: sec.FRPToken, serverID: acc.ServerID, connectionID: a.connectionID,
		adminHost: "127.0.0.1", adminPort: a.adminPort, adminUser: a.adminUser, adminPass: a.adminPass,
		trustedCA: a.cfg.TrustedCAFile, targets: tunnelled(st.Targets),
	}, nil
}

func (a *Agent) reconcile() error {
	d, err := a.desired()
	if err != nil {
		a.status.LastError = err.Error()
		a.stopProcess()
		return err
	}
	if d == nil {
		a.stopProcess()
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

// frpc is a static binary given absolute paths and an explicit CA file, so
// it needs no PATH, HOME, TZ or SSL_CERT_* from us.
var passEnv = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true,
}

func childEnv() []string {
	out := []string{}
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && passEnv[k] {
			out = append(out, kv)
		}
	}
	return out
}

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
