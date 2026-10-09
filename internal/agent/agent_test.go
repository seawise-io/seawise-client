package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

type harness struct {
	t      *testing.T
	dir    string
	st     *store.Store
	agent  *Agent
	log    string
	ctl    string
	timers *fakeTimers
	cancel context.CancelFunc
	runErr chan error
}

type fakeTimers struct {
	mu        sync.Mutex
	durations []time.Duration
	chans     []chan time.Time
}

func (f *fakeTimers) after(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := make(chan time.Time, 1)
	f.durations = append(f.durations, d)
	f.chans = append(f.chans, c)
	return c
}

func (f *fakeTimers) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.durations)
}

func (f *fakeTimers) fire(i int) {
	f.mu.Lock()
	c := f.chans[i]
	f.mu.Unlock()
	c <- time.Now()
}

func (f *fakeTimers) all() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.durations...)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func pairedStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: "sid", FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000, FRPUseTLS: true, APIURL: "https://api.example.invalid"}
		s.Targets = []store.Target{
			{LocalID: "a", Name: "jellyfin", Host: "192.168.1.20", Port: 8096, Subdomain: "jf", Source: store.SourceLocal},
			{LocalID: "b", Name: "off", Host: "192.168.1.21", Port: 80, Subdomain: "off", Disabled: true, Source: store.SourceLocal},
			{LocalID: "c", Name: "unregistered", Host: "192.168.1.22", Port: 81, Source: store.SourceLocal},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "synthetic-token"; return nil }); err != nil {
		t.Fatal(err)
	}
	return st
}

func newHarness(t *testing.T, st *store.Store, mode string, tweak func(*Config)) *harness {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: st, timers: &fakeTimers{}, runErr: make(chan error, 1)}
	tmp := t.TempDir()
	h.log = filepath.Join(tmp, "events")
	h.ctl = filepath.Join(tmp, "mode")
	h.setMode(mode)
	cfg := Config{
		Store:        st,
		FRPCPath:     exe,
		AdminPort:    freePort(t),
		StopTimeout:  2 * time.Second,
		PollInterval: 50 * time.Millisecond,
		After:        h.timers.after,
		Logger:       nil,
		Env:          append(os.Environ(), envFake+"=1", envFakeLog+"="+h.log, envFakeCtl+"="+h.ctl),
	}
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

func (h *harness) setMode(mode string) {
	if err := os.WriteFile(h.ctl, []byte(mode), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) events() []string {
	b, _ := os.ReadFile(h.log)
	return strings.Fields(strings.ReplaceAll(string(b), "\n", " | "))
}

func (h *harness) count(event string) int {
	b, _ := os.ReadFile(h.log)
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, event+" ") {
			n++
		}
	}
	return n
}

func (h *harness) overlaps() int {
	return h.count("overlap")
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

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestStartsFRPCWithAtomicConfig(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })

	info, err := os.Stat(h.agent.ConfigPath())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, %v", info, err)
	}
	b, _ := os.ReadFile(h.agent.ConfigPath())
	conf := string(b)
	for _, want := range []string{
		`serverAddr = "frp-1.seawise.dev"`,
		`transport.tls.serverName = "frp-1.seawise.dev"`,
		`metadatas.token = "synthetic-token"`,
		`metadatas.server_id = "sid"`,
		`webServer.addr = "127.0.0.1"`,
		`name = "sid-jellyfin"`,
		`subdomain = "jf"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "off") || strings.Contains(conf, "unregistered") {
		t.Errorf("disabled or unregistered target tunnelled:\n%s", conf)
	}
	if filepath.Dir(h.agent.ConfigPath()) != h.st.Dir() {
		t.Fatal("config not under v2")
	}
	entries, _ := os.ReadDir(h.st.Dir())
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}

	eventually(t, "admin status", func() bool {
		s := h.status()
		return len(s.Proxies) == 1 && s.Proxies[0].Name == "sid-jellyfin" && s.Proxies[0].Status == "running"
	})
}

func TestNoChangeNoRewriteNoRestart(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	pid := h.status().PID
	before, _ := os.Stat(h.agent.ConfigPath())
	for i := 0; i < 5; i++ {
		if err := h.agent.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.Stat(h.agent.ConfigPath())
	if !os.SameFile(before, after) || h.status().PID != pid || h.count("start") != 1 || h.count("reload") != 0 {
		t.Fatalf("unexpected rewrite or restart: %v", h.events())
	}
}

func TestTargetChangeReloadsInPlace(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	pid := h.status().PID
	err := h.st.Update(func(s *store.State) error {
		s.Targets = append(s.Targets, store.Target{LocalID: "d", Name: "kuma", Host: "kuma", Port: 3001, Subdomain: "k", Source: store.SourceLocal})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.count("reload") != 1 || h.status().PID != pid {
		t.Fatalf("expected in-place reload: %v", h.events())
	}
	eventually(t, "two proxies", func() bool { return len(h.status().Proxies) == 2 })
}

func TestServerChangeRestarts(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	pid := h.status().PID
	if err := h.st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "rotated"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); !s.Running || s.PID == pid {
		t.Fatalf("expected a new process: %+v", s)
	}
	if h.overlaps() != 0 {
		t.Fatalf("overlapping processes: %v", h.events())
	}
}

func TestCrashBackoffCappedAt30s(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "crash", nil)
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i := range want {
		want[i] *= time.Second
		eventually(t, "backoff timer", func() bool { return h.timers.count() == i+1 })
		h.timers.fire(i)
	}
	got := h.timers.all()[:len(want)]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff = %v, want %v", got, want)
		}
	}
	if h.overlaps() != 0 {
		t.Fatalf("overlapping processes: %v", h.events())
	}
}

func TestBackoffResetsAfterStableRun(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "crash", func(c *Config) { c.StableAfter = time.Nanosecond })
	for i := 0; i < 4; i++ {
		eventually(t, "backoff timer", func() bool { return h.timers.count() == i+1 })
		h.timers.fire(i)
	}
	for _, d := range h.timers.all()[:4] {
		if d != time.Second {
			t.Fatalf("backoff = %v, want reset to base each time", h.timers.all())
		}
	}
}

func TestBackoffFunction(t *testing.T) {
	for n := 1; n < 200; n++ {
		if d := backoff(n, DefaultBackoffBase, DefaultBackoffMax); d > 30*time.Second || d < time.Second {
			t.Fatalf("attempt %d: %v", n, d)
		}
	}
}

func TestReconcileDuringBackoffDoesNotStart(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "crash", nil)
	eventually(t, "first crash", func() bool { return h.timers.count() == 1 })
	h.setMode("run")
	for i := 0; i < 5; i++ {
		if err := h.agent.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s := h.status(); s.Running || h.count("start") != 1 || s.NextRestart != time.Second {
		t.Fatalf("backoff bypassed: %+v %v", s, h.events())
	}
	h.timers.fire(0)
	eventually(t, "restart after backoff", func() bool { return h.status().Running })
	if h.status().Restarts != 1 {
		t.Fatalf("restarts = %d", h.status().Restarts)
	}
}

func TestConcurrentIntentsKeepOneProcess(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < 10; i++ {
				switch (g + i) % 4 {
				case 0:
					_ = h.agent.Reconcile(ctx)
				case 1:
					_ = h.agent.Pause(ctx)
				case 2:
					_ = h.agent.Resume(ctx)
				case 3:
					_, _ = h.agent.Status(ctx)
				}
			}
		}(g)
	}
	wg.Wait()
	if err := h.agent.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	if h.overlaps() != 0 {
		t.Fatalf("overlapping processes: %v", h.events())
	}
}

func TestPauseResume(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { return len(h.status().Proxies) == 1 })
	if err := h.agent.Pause(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running || !s.Paused || h.count("exit") != 1 {
		t.Fatalf("pause: %+v %v", s, h.events())
	}
	if err := h.agent.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); !s.Running || s.Paused || s.Restarts != 0 {
		t.Fatalf("resume: %+v", s)
	}
}

func TestUnpairedDoesNotStart(t *testing.T) {
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running || h.count("start") != 0 {
		t.Fatalf("started while unpaired: %+v", s)
	}
}

func TestDisallowedServerRefused(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	if err := st.Update(func(s *store.State) error { s.Account.FRPServerAddr = "evil.example.com"; return nil }); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	if err := h.agent.Reconcile(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if s := h.status(); s.Running || s.LastError == "" || h.count("start") != 0 {
		t.Fatalf("status = %+v", s)
	}
	for _, addr := range []string{"seawise.dev.evil.com", "evilseawise.dev", "frp-1.seawise.dev.", ""} {
		if allowedServer(addr, []string{".seawise.dev"}) {
			t.Errorf("%q allowed", addr)
		}
	}
	if !allowedServer("FRP-2.SeaWise.dev", []string{".seawise.dev"}) {
		t.Error("case-insensitive match failed")
	}
}

func TestShutdownStopsFRPC(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { return len(h.status().Proxies) == 1 })
	h.stop()
	if h.count("exit") != 1 {
		t.Fatalf("frpc not stopped: %v", h.events())
	}
	if _, err := h.agent.Status(context.Background()); !errors.Is(err, ErrStopped) {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingBinaryRetriesWithBackoff(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", func(c *Config) { c.FRPCPath = "/nonexistent/frpc" })
	eventually(t, "backoff timer", func() bool { return h.timers.count() == 1 })
	if s := h.status(); s.Running || s.LastError == "" || s.NextRestart != time.Second {
		t.Fatalf("status = %+v", s)
	}
}

func TestAdminClientLoopbackOnly(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "192.168.1.1", "localhost", "example.com", ""} {
		if _, err := newAdminClient(host, 7400, "u", "p", time.Second); err == nil {
			t.Errorf("%q accepted", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		if _, err := newAdminClient(host, 7400, "u", "p", time.Second); err != nil {
			t.Errorf("%q refused: %v", host, err)
		}
	}
}

func TestAdminClientDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/status", http.StatusFound)
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	c, err := newAdminClient("127.0.0.1", port, "u", "p", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.status(context.Background()); err == nil {
		t.Fatal("redirect treated as success")
	}
	if hit {
		t.Fatal("redirect followed")
	}
}

func TestChildEnvFiltersSecrets(t *testing.T) {
	t.Setenv("SEAWISE_ADMIN_PASSWORD", "x")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.invalid:3128")
	env := strings.Join(childEnv(), "\n")
	if strings.Contains(env, "SEAWISE_ADMIN_PASSWORD") || !strings.Contains(env, "HTTPS_PROXY=") {
		t.Fatalf("env = %s", env)
	}
}

func TestRunOnV1VolumeLeavesV1FilesUnchanged(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("..", "legacy", "testdata", "v1", "E")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dir, rel), 0o700)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(filepath.Join(dir, rel), os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	hashes := func() map[string][32]byte {
		m := map[string][32]byte{}
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(dir, p)
			if rel == store.SubDir {
				return filepath.SkipDir
			}
			if !d.IsDir() {
				b, _ := os.ReadFile(p)
				m[rel] = sha256.Sum256(b)
			}
			return nil
		})
		return m
	}
	before := hashes()

	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *store.State) error { s.Account.FRPServerAddr = "frp-1.seawise.dev"; return nil }); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	h.stop()

	after := hashes()
	if len(before) != len(after) {
		t.Fatalf("v1 file set changed: %d -> %d", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("%s changed", k)
		}
	}
}
