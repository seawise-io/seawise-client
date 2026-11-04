package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
)

// fakeTunnel stands in for the session manager.
type fakeTunnel struct {
	up      bool
	started chan struct{}
	stopped chan struct{}
	fail    error
	proves  atomic.Int32
}

func (f *fakeTunnel) Run(ctx context.Context) error {
	close(f.started)
	defer close(f.stopped)
	if f.fail != nil {
		return f.fail
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeTunnel) Status() session.Status { return session.Status{State: "OWN", Up: f.up} }

type factory struct {
	mu      sync.Mutex
	err     error
	fail    error
	built   []*fakeTunnel
	retries chan chan time.Time
}

func (f *factory) build() (Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	t := &fakeTunnel{up: true, started: make(chan struct{}), stopped: make(chan struct{}), fail: f.fail}
	f.built = append(f.built, t)
	return t, nil
}

func (f *factory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.built)
}

func (f *factory) last() *fakeTunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.built[len(f.built)-1]
}

func (f *factory) set(err, fail error) {
	f.mu.Lock()
	f.err, f.fail = err, fail
	f.mu.Unlock()
}

type harness struct {
	t      *testing.T
	st     *store.Store
	agent  *Agent
	f      *factory
	cancel context.CancelFunc
	runErr chan error
}

var confirmed = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func pairedStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// The v1 control-plane backend still authenticates with this token.
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "synthetic-token"; return nil }); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b", APIURL: "https://api.example.invalid"}
		s.Targets = []store.Target{
			{LocalID: "a", Name: "jellyfin", Host: "192.168.1.20", Port: 8096, Subdomain: "jf", Source: store.SourceLocal, ConfirmedAt: &confirmed},
			{LocalID: "b", Name: "off", Host: "192.168.1.21", Port: 80, Subdomain: "off", Disabled: true, Source: store.SourceLocal},
			{LocalID: "c", Name: "unregistered", Host: "192.168.1.22", Port: 81, Source: store.SourceLocal},
			{LocalID: "m", Name: "metaapp", Host: "169.254.169.254", Port: 80, Subdomain: "m1", Source: store.SourceV1Machine, Grandfathered: true, ConfirmedAt: &confirmed},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func newHarness(t *testing.T, st *store.Store, tweak func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, st: st, f: &factory{retries: make(chan chan time.Time, 16)}, runErr: make(chan error, 1)}
	cfg := Config{Store: st, Tunnel: h.f.build, StopTimeout: 2 * time.Second,
		After: func(time.Duration) <-chan time.Time {
			c := make(chan time.Time, 1)
			h.f.retries <- c
			return c
		}}
	if tweak != nil {
		tweak(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.agent = a
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.runErr <- a.Run(ctx) }()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	h.cancel = nil
	select {
	case <-h.runErr:
	case <-time.After(10 * time.Second):
		h.t.Error("agent did not stop")
	}
}

func (h *harness) status() Status {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := h.agent.Status(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func (h *harness) fireRetry() {
	h.t.Helper()
	select {
	case c := <-h.f.retries:
		c <- time.Now()
	case <-time.After(5 * time.Second):
		h.t.Fatal("no retry armed")
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (a *Agent) fwdPorts() map[string]int { return a.ports }

func closed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func TestPairedStartsTunnel(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	s := h.status()
	if !s.Running || !s.Connected || s.Tunnel == nil || s.Tunnel.State != "OWN" || h.f.count() != 1 {
		t.Fatalf("%+v", s)
	}
	if len(s.Refused) != 1 || s.Refused[0].LocalID != "m" {
		t.Fatalf("refusals = %v", s.Refused)
	}
}

func TestUnpairedDoesNotStart(t *testing.T) {
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := newHarness(t, st, nil)
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running || h.f.count() != 0 {
		t.Fatalf("started while unpaired: %+v", s)
	}
}

func TestNotReadyIsRetried(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	f := &factory{err: fmt.Errorf("%w: waiting for the signed key set", ErrNotReady)}
	hh := newHarness(t, st, func(c *Config) { c.Tunnel = f.build })
	if s := hh.status(); s.Running || s.LastError == "" {
		t.Fatalf("%+v", s)
	}
	f.set(nil, nil)
	hh.fireRetry()
	eventually(t, "tunnel after retry", func() bool { return hh.status().Running })
	if hh.status().LastError != "" {
		t.Fatal("error kept after start")
	}
}

func TestOtherFactoryErrorReported(t *testing.T) {
	f := &factory{err: errors.New("broken")}
	h := newHarness(t, pairedStore(t, t.TempDir()), func(c *Config) { c.Tunnel = f.build })
	if err := h.agent.Reconcile(context.Background()); err == nil {
		t.Fatal("error not returned")
	}
}

func TestTunnelExitRestartsAfterRetry(t *testing.T) {
	f := &factory{fail: errors.New("crashed")}
	h := newHarness(t, pairedStore(t, t.TempDir()), func(c *Config) { c.Tunnel = f.build })
	eventually(t, "exit seen", func() bool { s := h.status(); return !s.Running && s.LastError != "" })
	f.set(nil, nil)
	h.fireRetry()
	eventually(t, "restarted", func() bool { return h.status().Running && f.count() == 2 })
}

func TestKillSwitchDropsEverything(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	h.status()
	tun := h.f.last()
	ports := h.agent.fwdPorts()
	if len(ports) != 1 {
		t.Fatalf("forwarders = %v", ports)
	}
	if err := h.agent.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	s := h.status()
	if s.Running || !s.Paused || len(s.Holds) != 1 || s.Holds[0] != HoldKillSwitch || !closed(tun.stopped) {
		t.Fatalf("status after kill switch: %+v", s)
	}
	for _, p := range ports {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), time.Second); err == nil {
			c.Close()
			t.Fatal("forwarder still listening")
		}
	}
	if !h.st.State().HasHold(store.HoldKillSwitch) {
		t.Fatal("kill switch not persisted")
	}
	if err := h.agent.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running {
		t.Fatal("resume released the kill switch")
	}
	if err := h.agent.SetKillSwitch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); !s.Running || s.Paused || h.st.State().HasHold(store.HoldKillSwitch) || h.f.count() != 2 {
		t.Fatalf("restore: %+v", s)
	}
}

func TestKillSwitchSurvivesRestart(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	if err := st.Update(func(s *store.State) error { s.Holds = []string{store.HoldKillSwitch}; return nil }); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, nil)
	if s := h.status(); s.Running || !s.Paused || h.f.count() != 0 {
		t.Fatalf("started with a persisted kill switch: %+v", s)
	}
	if err := h.agent.SetKillSwitch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !h.status().Running {
		t.Fatal("not restored")
	}
}

func TestKillSwitchTakesEffectWhenRequestIsCancelled(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = h.agent.SetKillSwitch(ctx, true)
	if !h.st.State().HasHold(store.HoldKillSwitch) {
		t.Fatal("not persisted")
	}
	eventually(t, "tunnel dropped", func() bool { return !h.status().Running })
}

func TestReleaseCannotClearKillSwitch(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	if err := h.agent.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Release(context.Background(), HoldKillSwitch); !errors.Is(err, ErrKillSwitchReason) {
		t.Fatal(err)
	}
	if err := h.agent.Hold(context.Background(), HoldKillSwitch); !errors.Is(err, ErrKillSwitchReason) {
		t.Fatal(err)
	}
	if s := h.status(); s.Running || !h.st.State().HasHold(store.HoldKillSwitch) {
		t.Fatalf("%+v", s)
	}
}

func TestPersistedKillSwitchAppliedWithoutIntent(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	if err := h.st.Update(func(s *store.State) error { s.Holds = []string{store.HoldKillSwitch}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running {
		t.Fatalf("%+v", s)
	}
}

func TestPauseResume(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	if err := h.agent.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running || !s.Paused {
		t.Fatalf("pause: %+v", s)
	}
	if err := h.agent.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); !s.Running || s.Paused {
		t.Fatalf("resume: %+v", s)
	}
}

func TestHoldsAreIndependent(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	ctx := context.Background()
	if err := h.agent.Hold(ctx, HoldRemoval); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Release(ctx, HoldRemoval); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running || !s.Paused || len(s.Holds) != 1 || s.Holds[0] != HoldUser {
		t.Fatalf("user hold released by another reason: %+v", s)
	}
	if err := h.agent.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); !s.Running || s.Paused {
		t.Fatalf("resume: %+v", s)
	}
	if err := h.agent.Hold(ctx, ""); err == nil {
		t.Fatal("empty hold reason accepted")
	}
}

func TestShutdownStopsTunnel(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	h.status()
	tun := h.f.last()
	h.stop()
	if !closed(tun.stopped) {
		t.Fatal("tunnel still running")
	}
	if _, err := h.agent.Status(context.Background()); !errors.Is(err, ErrStopped) {
		t.Fatal(err)
	}
}

func TestLeftoverFilesRemoved(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	for _, f := range leftoverFiles {
		if err := os.WriteFile(filepath.Join(st.Dir(), f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := newHarness(t, st, nil)
	h.status()
	for _, f := range leftoverFiles {
		if _, err := os.Stat(filepath.Join(st.Dir(), f)); !os.IsNotExist(err) {
			t.Fatalf("%s left: %v", f, err)
		}
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("no store accepted")
	}
	st := pairedStore(t, t.TempDir())
	if _, err := New(Config{Store: st}); err == nil {
		t.Fatal("no tunnel factory accepted")
	}
	a, err := New(Config{Store: st, Tunnel: (&factory{}).build})
	if err != nil || len(a.ConnectionID()) != 32 || a.cfg.Retry != DefaultRetry || a.cfg.StopTimeout != DefaultStopTimeout {
		t.Fatal(a, err)
	}
}

func (f *fakeTunnel) ProveRotation() error {
	f.proves.Add(1)
	return nil
}

func TestProveRotationAsksTheSessionManager(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	h.status()
	tun := h.f.last()
	if err := h.agent.ProveRotation(context.Background()); err != nil || tun.proves.Load() != 1 {
		t.Fatalf("err %v, proves %d", err, tun.proves.Load())
	}
}

func TestProveRotationNeedsRunningTunnel(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), func(c *Config) {
		c.Tunnel = func() (Tunnel, error) { return nil, fmt.Errorf("%w: no device key yet", ErrNotReady) }
	})
	if err := h.agent.ProveRotation(context.Background()); !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("err %v", err)
	}
}
