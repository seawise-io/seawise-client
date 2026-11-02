package healthprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

type reports struct {
	mu  sync.Mutex
	got []map[string]string
	ch  chan map[string]string
}

func newReports() *reports { return &reports{ch: make(chan map[string]string, 64)} }

func (r *reports) report(m map[string]string) {
	r.mu.Lock()
	r.got = append(r.got, m)
	r.mu.Unlock()
	r.ch <- m
}

func (r *reports) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func (r *reports) last(t *testing.T) map[string]string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) == 0 {
		t.Fatal("no report")
	}
	return r.got[len(r.got)-1]
}

func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// closedPort returns a loopback port with nothing listening.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func portOf(ln net.Listener) int { return ln.Addr().(*net.TCPAddr).Port }

func app(id, host string, port int) store.Target {
	return store.Target{LocalID: id, Name: id, Host: host, Port: port, Subdomain: "sub-" + id}
}

type targets struct {
	mu sync.Mutex
	ts []store.Target
}

func (s *targets) get() []store.Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Target(nil), s.ts...)
}

func (s *targets) set(ts ...store.Target) {
	s.mu.Lock()
	s.ts = ts
	s.mu.Unlock()
}

func newProber(t *testing.T, ts *targets, r *reports, mod func(*Config)) *Prober {
	t.Helper()
	cfg := Config{Targets: ts.get, Report: r.report, Timeout: time.Second}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoundReportsUpDownAndUpAgain(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	addr := ln.Addr().String()
	ts := &targets{}
	ts.set(app("a", "127.0.0.1", portOf(ln)))
	r := newReports()
	p := newProber(t, ts, r, nil)
	ctx := context.Background()

	p.round(ctx)
	if got := r.last(t); len(got) != 1 || got["a"] != Online {
		t.Fatalf("first round %v", got)
	}
	_ = ln.Close()
	p.round(ctx)
	if r.count() != 2 || r.last(t)["a"] != Offline {
		t.Fatalf("after close: %d reports, last %v", r.count(), r.last(t))
	}
	listen(t, addr)
	p.round(ctx)
	if r.count() != 3 || r.last(t)["a"] != Online {
		t.Fatalf("after reopen: %d reports, last %v", r.count(), r.last(t))
	}
}

// Every round sends the full snapshot, so a report the server refused or
// filtered is sent again on the next round.
func TestEveryRoundReportsFullSnapshot(t *testing.T) {
	up := listen(t, "127.0.0.1:0")
	down := closedPort(t)
	ts := &targets{}
	ts.set(app("a", "127.0.0.1", portOf(up)), app("b", "localhost", down))
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	ctx := context.Background()
	p.round(ctx)
	p.round(ctx)
	if got := r.last(t); r.count() != 2 || len(got) != 2 || got["a"] != Online || got["b"] != Offline {
		t.Fatalf("unchanged round: %d reports, last %v", r.count(), got)
	}
	listen(t, "127.0.0.1:"+strconv.Itoa(down))
	p.round(ctx)
	if got := r.last(t); len(got) != 2 || got["a"] != Online || got["b"] != Online {
		t.Fatalf("change report %v", got)
	}
	ts.set(app("a", "127.0.0.1", portOf(up)), app("c", "127.0.0.1", portOf(up)))
	p.round(ctx)
	if got := r.last(t); len(got) != 2 || got["a"] != Online || got["c"] != Online {
		t.Fatalf("after replacing an app %v", got)
	}
}

func TestAppLeavingProbedSetReportedOffline(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	a := app("a", "127.0.0.1", portOf(ln))
	ts.set(a)
	r := newReports()
	p := newProber(t, ts, r, nil)
	p.round(context.Background())
	if r.last(t)["a"] != Online {
		t.Fatalf("%v", r.last(t))
	}
	a.Disabled = true
	ts.set(a)
	p.round(context.Background())
	if got := r.last(t); len(got) != 1 || got["a"] != Offline {
		t.Fatalf("disabled app %v", got)
	}
}

func TestReportIsACopy(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	ts.set(app("a", "127.0.0.1", portOf(ln)))
	r := newReports()
	p := newProber(t, ts, r, nil)
	p.round(context.Background())
	r.last(t)["a"] = "tampered"
	p.round(context.Background())
	if r.last(t)["a"] != Online {
		t.Fatalf("changing a delivered report changed the next one: %v", r.last(t))
	}
}

func TestOnlyTunnelledAppsAreProbed(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	port := portOf(ln)
	disabled := app("disabled", "disabled.example", port)
	disabled.Disabled = true
	unconfirmed := app("unconfirmed", "unconfirmed.example", port)
	unconfirmed.Subdomain = ""
	ts := &targets{}
	ts.set(app("ok", "ok.example", port), disabled, unconfirmed,
		app("zero", "zero.example", 0), app("big", "big.example", 65536), app("max", "max.example", 65535), app("one", "one.example", 1))
	var mu sync.Mutex
	var resolved []string
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.Resolve = func(_ context.Context, h string) ([]netip.Addr, error) {
			mu.Lock()
			resolved = append(resolved, h)
			mu.Unlock()
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	p.round(context.Background())
	got := r.last(t)
	if len(got) != 4 || got["ok"] != Online || got["max"] == "" || got["one"] == "" || got["disabled"] != Offline {
		t.Fatalf("report %v", got)
	}
	for _, id := range []string{"unconfirmed", "zero", "big"} {
		if _, ok := got[id]; ok {
			t.Fatalf("%s reported: %q", id, got[id])
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resolved) != 3 {
		t.Fatalf("resolved %v", resolved)
	}
	for _, h := range resolved {
		if h != "ok.example" && h != "max.example" && h != "one.example" {
			t.Fatalf("probed %s", h)
		}
	}
}

func TestNoAppsNoReport(t *testing.T) {
	r := newReports()
	p := newProber(t, &targets{}, r, nil)
	p.round(context.Background())
	if r.count() != 0 {
		t.Fatal("empty round reported")
	}
}

func TestPolicyRefusedTargetsAreNeverConnected(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	port := portOf(ln)
	var mu sync.Mutex
	var connected []string
	base := &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		mu.Lock()
		connected = append(connected, address)
		mu.Unlock()
		return nil
	}}
	ts := &targets{}
	ts.set(
		app("metadata", "169.254.169.254", port),
		app("linklocal", "[fe80::1]", port),
		app("thisnet", "0.0.0.0", port),
		app("named", "metadata.example", port),
		app("mixed", "mixed.example", port),
	)
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.Dialer = base
		c.Resolve = func(_ context.Context, h string) ([]netip.Addr, error) {
			if h == "mixed.example" {
				return []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("127.0.0.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
	})
	p.round(context.Background())
	got := r.last(t)
	for _, id := range []string{"metadata", "linklocal", "thisnet", "named"} {
		if got[id] != Offline {
			t.Fatalf("%s: %q", id, got[id])
		}
	}
	if got["mixed"] != Online {
		t.Fatalf("mixed: %q", got["mixed"])
	}
	mu.Lock()
	defer mu.Unlock()
	want := "127.0.0.1:" + strconv.Itoa(port)
	if len(connected) != 1 || connected[0] != want {
		t.Fatalf("connected to %v, want only %s", connected, want)
	}
}

func TestResolveFailureIsOffline(t *testing.T) {
	ts := &targets{}
	ts.set(app("a", "nowhere.example", 80))
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	})
	p.round(context.Background())
	if r.last(t)["a"] != Offline {
		t.Fatalf("%v", r.last(t))
	}
}

func TestProbeTimeout(t *testing.T) {
	ts := &targets{}
	ts.set(app("a", "slow.example", 80))
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.Timeout = 50 * time.Millisecond
		c.Resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	start := time.Now()
	p.round(context.Background())
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("probe took %v", d)
	}
	if r.last(t)["a"] != Offline {
		t.Fatalf("%v", r.last(t))
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	var inFlight, peak atomic.Int32
	ts := &targets{}
	var apps []store.Target
	for i := range 20 {
		apps = append(apps, app("a"+strconv.Itoa(i), "h"+strconv.Itoa(i)+".example", portOf(ln)))
	}
	ts.set(apps...)
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.Workers = 3
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			n := inFlight.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	p.round(context.Background())
	if got := peak.Load(); got != 3 {
		t.Fatalf("peak concurrency %d, want 3", got)
	}
	if got := r.last(t); len(got) != 20 {
		t.Fatalf("report has %d apps", len(got))
	}
}

func TestCancelledRoundDoesNotReport(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	var apps []store.Target
	for i := range 4 {
		apps = append(apps, app("a"+strconv.Itoa(i), "127.0.0.1", portOf(ln)))
	}
	ts.set(apps...)
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) { c.Workers = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.round(ctx)
	if r.count() != 0 {
		t.Fatal("cancelled round reported")
	}
}

func TestRunProbesOnlyWhileConnectedAndReReportsAfterReconnect(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	ts.set(app("a", "127.0.0.1", portOf(ln)))
	r := newReports()
	var up atomic.Bool
	p := newProber(t, ts, r, func(c *Config) {
		c.StartDelay = 10 * time.Millisecond
		c.Interval = time.Hour
		c.CheckEvery = 5 * time.Millisecond
		c.Connected = up.Load
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	time.Sleep(60 * time.Millisecond)
	if r.count() != 0 {
		t.Fatal("probed while the tunnel was down")
	}
	up.Store(true)
	waitReport(t, r, Online)
	time.Sleep(40 * time.Millisecond)
	if r.count() != 1 {
		t.Fatalf("reported again before the interval: %d", r.count())
	}
	up.Store(false)
	time.Sleep(40 * time.Millisecond)
	up.Store(true)
	waitReport(t, r, Online)
	cancel()
	<-done
}

func TestRunRepeatsEveryInterval(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	ts.set(app("a", "127.0.0.1", portOf(ln)))
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.StartDelay = time.Millisecond
		c.Interval = 30 * time.Millisecond
		c.CheckEvery = 5 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	waitReport(t, r, Online)
	_ = ln.Close()
	waitReport(t, r, Offline)
	cancel()
	<-done
}

func TestRunWaitsForStartDelay(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	ts.set(app("a", "127.0.0.1", portOf(ln)))
	r := newReports()
	p := newProber(t, ts, r, func(c *Config) {
		c.StartDelay = time.Hour
		c.CheckEvery = time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done
	if r.count() != 0 {
		t.Fatal("probed before the start delay")
	}
}

func waitReport(t *testing.T, r *reports, want string) {
	t.Helper()
	select {
	case m := <-r.ch:
		if m["a"] != want {
			t.Fatalf("report %v, want a=%s", m, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no report with a=%s", want)
	}
}

func TestNewDefaultsAndRequiredFields(t *testing.T) {
	if _, err := New(Config{Report: func(map[string]string) {}}); err == nil {
		t.Fatal("no Targets accepted")
	}
	if _, err := New(Config{Targets: func() []store.Target { return nil }}); err == nil {
		t.Fatal("no Report accepted")
	}
	p, err := New(Config{Targets: func() []store.Target { return nil }, Report: func(map[string]string) {}})
	if err != nil {
		t.Fatal(err)
	}
	c := p.cfg
	if c.StartDelay != 10*time.Second || c.Interval != 30*time.Second || c.Timeout != 3*time.Second ||
		c.CheckEvery != 5*time.Second || c.Workers != 8 || c.Resolve == nil || c.Dialer == nil ||
		c.Connected == nil || !c.Connected() {
		t.Fatalf("defaults %+v", c)
	}
	p, err = New(Config{Targets: func() []store.Target { return nil }, Report: func(map[string]string) {},
		StartDelay: 1, Interval: 2, Timeout: 3, CheckEvery: 4, Workers: 5})
	if err != nil {
		t.Fatal(err)
	}
	c = p.cfg
	if c.StartDelay != 1 || c.Interval != 2 || c.Timeout != 3 || c.CheckEvery != 4 || c.Workers != 5 {
		t.Fatalf("overrides %+v", c)
	}
}

func TestDefaultResolverResolvesLocalhost(t *testing.T) {
	p, err := New(Config{Targets: func() []store.Target { return nil }, Report: func(map[string]string) {}})
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := p.cfg.Resolve(context.Background(), "localhost")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("%v %v", addrs, err)
	}
}

func TestNewAppNeverReportedOfflineBeforeItIsProbed(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	ts := &targets{}
	a := app("a", "127.0.0.1", portOf(ln))
	a.Subdomain = ""
	ts.set(a)
	r := newReports()
	p := newProber(t, ts, r, nil)
	p.round(context.Background())
	if r.count() != 0 {
		t.Fatalf("unregistered app reported: %v", r.last(t))
	}
	a.Subdomain = "sub-a"
	ts.set(a)
	p.round(context.Background())
	for _, m := range r.got {
		if m["a"] != Online {
			t.Fatalf("report %v", m)
		}
	}
	if r.count() != 1 {
		t.Fatalf("reports %d", r.count())
	}
}
