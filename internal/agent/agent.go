// Package agent runs the client v2 reconcile loop. One goroutine owns the
// tunnel session and the loopback forwarder; everything else sends it
// intents.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

// Defaults.
const (
	DefaultRetry       = 30 * time.Second
	DefaultStopTimeout = 5 * time.Second
)

// Files earlier builds kept in the data folder; they held the frp token
// and the admin password.
var leftoverFiles = []string{"frpc.toml", "frpc.pid"}

var ErrStopped = errors.New("agent stopped")

// ErrNotReady wraps a missing tunnel prerequisite.
var ErrNotReady = errors.New("tunnel not ready")

// Tunnel is one run of the session manager.
type Tunnel interface {
	Run(ctx context.Context) error
	Status() session.Status
}

type Config struct {
	Store *store.Store
	// Tunnel builds the session manager for the paired server; an error
	// wrapping ErrNotReady names what is missing and is retried.
	Tunnel func() (Tunnel, error)
	// Retry is how long to wait before building the tunnel again.
	Retry       time.Duration
	StopTimeout time.Duration
	After       func(time.Duration) <-chan time.Time
	Logger      *slog.Logger
	// Gateways are this host's default gateways, for the target policy.
	Gateways []netip.Addr
	// Forward configures the loopback forwarder data streams go through.
	Forward forwarder.Config
}

// RefusedApp is an app the agent does not tunnel, with the reason.
type RefusedApp struct {
	LocalID string `json:"local_id"`
	Reason  string `json:"reason"`
}

type Status struct {
	// Running is true while the session manager runs.
	Running bool
	// Connected is true while a tunnel session is up.
	Connected bool
	Paused    bool
	Holds     []string
	LastError string
	Refused   []RefusedApp
	Tunnel    *session.Status `json:",omitempty"`
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

type running struct {
	tunnel Tunnel
	cancel context.CancelFunc
	done   chan error
}

type Agent struct {
	cfg     Config
	log     *slog.Logger
	intents chan intent
	done    chan struct{}

	// Owned by the loop goroutine.
	holds        map[string]bool
	fwd          *forwarder.Forwarder
	tunnel       *running
	ports        map[string]int // loopback forwarder port per admitted app
	retryAt      <-chan time.Time
	connectionID string
	status       Status
	runCtx       context.Context
}

func New(cfg Config) (*Agent, error) {
	if cfg.Store == nil {
		return nil, errors.New("store required")
	}
	if cfg.Tunnel == nil {
		return nil, errors.New("tunnel factory required")
	}
	if cfg.Retry <= 0 {
		cfg.Retry = DefaultRetry
	}
	if cfg.StopTimeout <= 0 {
		cfg.StopTimeout = DefaultStopTimeout
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
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
		done:         make(chan struct{}),
		connectionID: hex.EncodeToString(id),
		holds:        map[string]bool{},
		fwd:          forwarder.New(fwdCfg),
	}, nil
}

// Run owns the tunnel until ctx is cancelled, then stops it.
func (a *Agent) Run(ctx context.Context) error {
	defer close(a.done)
	a.runCtx = ctx
	a.removeLeftovers()
	_ = a.reconcile()
	for {
		var tunnelDone chan error
		if a.tunnel != nil {
			tunnelDone = a.tunnel.done
		}
		select {
		case <-ctx.Done():
			a.dropAll()
			return ctx.Err()
		case in := <-a.intents:
			in.reply <- a.handle(in)
		case err := <-tunnelDone:
			a.tunnel = nil
			a.status.LastError = fmt.Sprint("tunnel stopped: ", err)
			a.log.Warn("tunnel stopped", "error", err)
			a.retryAt = a.cfg.After(a.cfg.Retry)
		case <-a.retryAt:
			a.retryAt = nil
			_ = a.reconcile()
		}
	}
}

func (a *Agent) removeLeftovers() {
	for _, f := range leftoverFiles {
		err := os.Remove(filepath.Join(a.cfg.Store.Dir(), f))
		switch {
		case err == nil:
			a.log.Info("removed a file left by an earlier version", "file", f)
		case !errors.Is(err, os.ErrNotExist):
			a.log.Warn("remove leftover file", "file", f, "error", err)
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
	s.Holds = a.currentHolds()
	s.Paused = len(s.Holds) > 0
	s.Refused = append([]RefusedApp(nil), a.status.Refused...)
	if a.tunnel != nil {
		ts := a.tunnel.tunnel.Status()
		s.Running, s.Connected, s.Tunnel = true, ts.Up, &ts
	}
	return s
}

func (a *Agent) ctx() context.Context {
	if a.runCtx != nil {
		return a.runCtx
	}
	return context.Background()
}

func (a *Agent) reconcile() error {
	st := a.cfg.Store.State()
	if len(a.currentHolds()) > 0 || st.Account == nil {
		a.dropAll()
		return nil
	}
	a.syncForwarder(st.Targets)
	if a.tunnel != nil {
		return nil
	}
	t, err := a.cfg.Tunnel()
	if err != nil {
		a.status.LastError = err.Error()
		if a.retryAt == nil {
			a.retryAt = a.cfg.After(a.cfg.Retry)
		}
		if errors.Is(err, ErrNotReady) {
			a.log.Info("tunnel waiting", "reason", err)
			return nil
		}
		a.log.Warn("tunnel not started", "error", err)
		return err
	}
	a.status.LastError = ""
	ctx, cancel := context.WithCancel(a.ctx())
	r := &running{tunnel: t, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- t.Run(ctx) }()
	a.tunnel = r
	return nil
}

// syncForwarder admits targets through the policy and keeps one loopback
// forwarder listener per admitted app.
func (a *Agent) syncForwarder(targets []store.Target) {
	ok, refused := admit(targets, a.cfg.Gateways)
	a.status.Refused = refused
	apps := make([]forwarder.App, 0, len(ok))
	for _, t := range ok {
		apps = append(apps, forwarder.App{ID: t.LocalID, Host: t.Host, Port: t.Port, Rule: targetpolicy.RuleFor(t)})
	}
	a.ports = a.fwd.Sync(apps)
}

// dropAll closes every forwarder listener and connection first, so no
// visitor gets through while the session closes, then stops the tunnel.
func (a *Agent) dropAll() {
	a.ports = a.fwd.Sync(nil)
	a.stopTunnel()
}

func (a *Agent) stopTunnel() {
	r := a.tunnel
	if r == nil {
		return
	}
	a.tunnel = nil
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(a.cfg.StopTimeout):
		a.log.Warn("tunnel did not stop in time")
	}
}
