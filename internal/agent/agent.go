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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
)

const (
	DefaultAdminPort    = 7400
	DefaultBackoffBase  = time.Second
	DefaultBackoffMax   = 30 * time.Second
	DefaultStableAfter  = time.Minute
	DefaultStopTimeout  = 5 * time.Second
	DefaultPollInterval = 10 * time.Second
	DefaultTrustedCA    = "/etc/ssl/certs/ca-certificates.crt"
	ConfigFile          = "frpc.toml"
)

var ErrStopped = errors.New("agent stopped")

type Config struct {
	Store          *store.Store
	FRPCPath       string
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
	// Env is the frpc environment; nil passes only proxy, CA and locale
	// variables from the current process.
	Env []string
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
	admin   *adminClient
	intents chan intent
	exits   chan exitEvent
	polls   chan pollEvent
	done    chan struct{}

	// Owned by the loop goroutine.
	proc          *process
	holds         map[string]bool
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
	if cfg.AdminPort == 0 {
		cfg.AdminPort = DefaultAdminPort
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
	admin, err := newAdminClient("127.0.0.1", cfg.AdminPort, user, pass, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg:          cfg,
		log:          cfg.Logger.With("component", "agent"),
		admin:        admin,
		intents:      make(chan intent),
		exits:        make(chan exitEvent, 4),
		polls:        make(chan pollEvent, 1),
		done:         make(chan struct{}),
		adminUser:    user,
		adminPass:    pass,
		connectionID: connID,
		holds:        map[string]bool{},
	}, nil
}

func (a *Agent) ConfigPath() string {
	return filepath.Join(a.cfg.Store.Dir(), ConfigFile)
}

// Run owns frpc until ctx is cancelled, then stops it.
func (a *Agent) Run(ctx context.Context) error {
	defer close(a.done)
	a.runCtx = ctx
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()

	a.reconcile()
	for {
		select {
		case <-ctx.Done():
			a.stopProcess()
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

// ConnectionID identifies this agent run to the control plane.
func (a *Agent) ConnectionID() string { return a.connectionID }

func (a *Agent) Reconcile(ctx context.Context) error {
	_, err := a.send(ctx, intentReconcile, "")
	return err
}

func (a *Agent) Pause(ctx context.Context) error { return a.Hold(ctx, HoldUser) }

func (a *Agent) Resume(ctx context.Context) error { return a.Release(ctx, HoldUser) }

// Hold stops tunnels until every hold is released.
func (a *Agent) Hold(ctx context.Context, reason string) error {
	_, err := a.send(ctx, intentHold, reason)
	return err
}

func (a *Agent) Release(ctx context.Context, reason string) error {
	_, err := a.send(ctx, intentRelease, reason)
	return err
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

func (a *Agent) snapshot() Status {
	s := a.status
	s.Paused = len(a.holds) > 0
	s.Holds = make([]string, 0, len(a.holds))
	for h := range a.holds {
		s.Holds = append(s.Holds, h)
	}
	sort.Strings(s.Holds)
	s.Proxies = append([]ProxyStatus(nil), a.status.Proxies...)
	if a.proc != nil {
		s.Running, s.PID = true, a.proc.pid
	}
	return s
}

func (a *Agent) desired() (*desired, error) {
	if len(a.holds) > 0 {
		return nil, nil
	}
	st := a.cfg.Store.State()
	sec := a.cfg.Store.Secrets()
	if st.Account == nil || sec.FRPToken == "" {
		return nil, nil
	}
	acc := st.Account
	if !allowedServer(acc.FRPServerAddr, a.cfg.AllowedDomains) {
		return nil, fmt.Errorf("frp server %q is not an allowed domain", acc.FRPServerAddr)
	}
	if acc.FRPServerPort < 1 || acc.FRPServerPort > 65535 {
		return nil, fmt.Errorf("frp server port %d out of range", acc.FRPServerPort)
	}
	ca := ""
	if acc.FRPUseTLS {
		ca = a.cfg.TrustedCAFile
	}
	return &desired{
		serverAddr: acc.FRPServerAddr, serverPort: acc.FRPServerPort, useTLS: acc.FRPUseTLS,
		token: sec.FRPToken, serverID: acc.ServerID, connectionID: a.connectionID,
		adminHost: "127.0.0.1", adminPort: a.cfg.AdminPort, adminUser: a.adminUser, adminPass: a.adminPass,
		trustedCA: ca, targets: tunnelled(st.Targets),
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

	common, proxies := d.renderCommon(), d.renderProxies()
	commonChanged := common != a.writtenCommon
	proxiesChanged := proxies != a.writtenProxy
	if commonChanged || proxiesChanged || !fileExists(a.ConfigPath()) {
		data := []byte(common + proxies)
		if err := store.WriteFileAtomic(a.ConfigPath(), data, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
			a.status.LastError = err.Error()
			return err
		}
		a.writtenCommon, a.writtenProxy = common, proxies
		sum := sha256.Sum256(data)
		a.status.ConfigSHA256 = hex.EncodeToString(sum[:])
	}

	if a.proc == nil {
		if a.restartAt != nil {
			return nil
		}
		return a.startProcess()
	}
	switch {
	case commonChanged:
		a.stopProcess()
		return a.startProcess()
	case proxiesChanged:
		ctx, cancel := context.WithTimeout(a.ctx(), 3*time.Second)
		defer cancel()
		if err := a.admin.reload(ctx); err != nil {
			a.log.Warn("frpc reload failed, restarting", "error", err)
			a.stopProcess()
			return a.startProcess()
		}
	}
	return nil
}

func (a *Agent) ctx() context.Context {
	if a.runCtx != nil {
		return a.runCtx
	}
	return context.Background()
}

func (a *Agent) startProcess() error {
	cmd := exec.Command(a.cfg.FRPCPath, "-c", a.ConfigPath())
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
	a.log.Info("frpc stopped", "pid", p.pid)
}

func (a *Agent) onExit(ev exitEvent) {
	if a.proc == nil || ev.pid != a.proc.pid {
		return
	}
	p := a.proc
	a.proc = nil
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
	pid := a.proc.pid
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		proxies, err := a.admin.status(ctx)
		select {
		case a.polls <- pollEvent{pid: pid, proxies: proxies, err: err}:
		case <-a.done:
		}
	}()
}

var passEnv = map[string]bool{
	"PATH": true, "HOME": true, "TZ": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
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
