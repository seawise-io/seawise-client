package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func caFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, []byte("synthetic placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func confValue(t *testing.T, path, key string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, " = "); ok && k == key {
			return v
		}
	}
	return ""
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
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "synthetic-token"; return nil }); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: "sid", FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000, APIURL: "https://api.example.invalid"}
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
		Store:         st,
		FRPCPath:      exe,
		TrustedCAFile: caFile(t),
		StopTimeout:   2 * time.Second,
		PollInterval:  50 * time.Millisecond,
		After:         h.timers.after,
		Logger:        nil,
		Env:           append(os.Environ(), envFake+"=1", envFakeLog+"="+h.log, envFakeCtl+"="+h.ctl),
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
		`transport.tls.enable = true`,
		`transport.tls.trustedCaFile = "` + h.agent.cfg.TrustedCAFile + `"`,
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

func TestHoldsAreIndependent(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { return len(h.status().Proxies) == 1 })
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
	t.Setenv("no_proxy", "localhost")
	t.Setenv("HOME", "/home/someone")
	t.Setenv("TZ", "UTC")
	for _, kv := range childEnv() {
		k, _, _ := strings.Cut(kv, "=")
		if !strings.HasSuffix(strings.ToUpper(k), "_PROXY") {
			t.Fatalf("non-proxy variable passed to frpc: %s", k)
		}
	}
	if env := strings.Join(childEnv(), "\n"); !strings.Contains(env, "HTTPS_PROXY=") || !strings.Contains(env, "no_proxy=") {
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

func TestGroupAImportUsesVerifiedTLS(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("..", "legacy", "testdata", "v1", "A")
	for _, f := range []string{"config.json", "frpc.toml", "password.hash"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, f), b, 0o600)
	}
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if st.State().Account.ImportedFRPUseTLS {
		t.Fatal("fixture should have TLS off in v1")
	}
	if err := st.Update(func(s *store.State) error { s.Account.FRPServerAddr = "frp-1.seawise.dev"; return nil }); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	p := h.agent.ConfigPath()
	if confValue(t, p, "transport.tls.enable") != "true" || confValue(t, p, "transport.tls.trustedCaFile") != `"`+h.agent.cfg.TrustedCAFile+`"` || confValue(t, p, "transport.tls.serverName") != `"frp-1.seawise.dev"` {
		b, _ := os.ReadFile(p)
		t.Fatalf("config without verified TLS:\n%s", b)
	}
}

func TestMissingCABundleRefusesToStart(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", func(c *Config) { c.TrustedCAFile = "/nonexistent/ca.pem" })
	err := h.agent.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "certificate verification") {
		t.Fatalf("err = %v", err)
	}
	if s := h.status(); s.Running || h.count("start") != 0 {
		t.Fatalf("started without a CA bundle: %+v", s)
	}
	if _, err := os.Stat(h.agent.ConfigPath()); err == nil {
		t.Fatal("config written without a CA bundle")
	}
}

func TestAdminPortChangesPerStartAndStaysLoopback(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	h := newHarness(t, st, "run", nil)
	ports := map[string]bool{}
	for i := 0; i < 3; i++ {
		eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
		if confValue(t, h.agent.ConfigPath(), "webServer.addr") != `"127.0.0.1"` {
			t.Fatal("admin API not on loopback")
		}
		ports[confValue(t, h.agent.ConfigPath(), "webServer.port")] = true
		tok := fmt.Sprintf("token-%d", i)
		if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = tok; return nil }); err != nil {
			t.Fatal(err)
		}
		if err := h.agent.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(ports) < 2 {
		t.Fatalf("admin port reused across starts: %v", ports)
	}
}

const (
	envTestAgent    = "SEAWISE_TEST_AGENT"
	envTestAgentDir = "SEAWISE_TEST_AGENT_DIR"
	envTestAgentCA  = "SEAWISE_TEST_AGENT_CA"
)

// runTestAgent is the body of a separate agent process used by the
// cross-process tests.
func runTestAgent() {
	st, err := store.Open(os.Getenv(envTestAgentDir), time.Now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	exe, _ := os.Executable()
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, envTestAgent) {
			env = append(env, kv)
		}
	}
	a, err := New(Config{Store: st, FRPCPath: exe, TrustedCAFile: os.Getenv(envTestAgentCA), Env: append(env, envFake+"=1")})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	_ = a.Run(context.Background())
}

type agentProc struct {
	cmd    *exec.Cmd
	stderr *strings.Builder
}

func startAgentProcess(t *testing.T, dir, log, ctl string) *agentProc {
	t.Helper()
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), envTestAgent+"=1", envTestAgentDir+"="+dir, envTestAgentCA+"="+caFile(t), envFakeLog+"="+log, envFakeCtl+"="+ctl)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// A leaked frpc would hold the stderr pipe open; do not wait on it.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return &agentProc{cmd: cmd, stderr: &stderr}
}

func pidsFromLog(path, event string) []int {
	b, _ := os.ReadFile(path)
	var out []int
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, event+" "); ok {
			if n, err := strconv.Atoi(rest); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func pairedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	st := pairedStore(t, dir)
	st.Close()
	return dir
}

func TestSecondAgentOnSameDataDirRefused(t *testing.T) {
	dir := pairedDir(t)
	tmp := t.TempDir()
	log, ctl := filepath.Join(tmp, "events"), filepath.Join(tmp, "mode")
	os.WriteFile(ctl, []byte("run"), 0o600)
	startAgentProcess(t, dir, log, ctl)
	eventually(t, "first agent started frpc", func() bool { return len(pidsFromLog(log, "start")) == 1 })

	if _, err := store.Open(dir, time.Now); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("in-process open: err = %v", err)
	}
	second := startAgentProcess(t, dir, log, ctl)
	err := second.cmd.Wait()
	if err == nil || !strings.Contains(second.stderr.String(), "another agent") {
		t.Fatalf("second agent: err %v stderr %q", err, second.stderr.String())
	}
	if n := len(pidsFromLog(log, "start")); n != 1 {
		t.Fatalf("second agent started frpc: %d starts", n)
	}
}

func TestKilledAgentLeavesNoFRPC(t *testing.T) {
	dir := pairedDir(t)
	tmp := t.TempDir()
	log, ctl := filepath.Join(tmp, "events"), filepath.Join(tmp, "mode")
	os.WriteFile(ctl, []byte("run"), 0o600)
	ap := startAgentProcess(t, dir, log, ctl)
	eventually(t, "frpc started", func() bool { return len(pidsFromLog(log, "start")) == 1 })
	frpcPID := pidsFromLog(log, "start")[0]
	if !procAlive(frpcPID) {
		t.Fatal("frpc not alive")
	}
	if err := ap.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = ap.cmd.Wait()
	if !waitGone(frpcPID, 5*time.Second) {
		t.Fatalf("frpc %d survived the agent", frpcPID)
	}
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatalf("lock not released by dead agent: %v", err)
	}
	st.Close()
}

func startLooseFRPC(t *testing.T, configPath string) (*exec.Cmd, string) {
	t.Helper()
	exe, _ := os.Executable()
	tmp := t.TempDir()
	log := filepath.Join(tmp, "events")
	cmd := exec.Command(exe, "-c", configPath)
	cmd.Env = append(os.Environ(), envFake+"=1", envFakeLog+"="+log, envFakeCtl+"="+filepath.Join(tmp, "mode"))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, "loose frpc up", func() bool { return len(pidsFromLog(log, "start")) == 1 })
	return cmd, log
}

func TestStaleFRPCFromPreviousAgentIsStopped(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	exe, _ := os.Executable()
	prev, err := New(Config{Store: st, FRPCPath: exe, TrustedCAFile: caFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(prev.ConfigPath(), []byte(fmt.Sprintf("webServer.port = %d\n", freePort(t))), 0o600)
	stale, staleLog := startLooseFRPC(t, prev.ConfigPath())
	if err := prev.recordPID(stale.Process.Pid); err != nil {
		t.Fatal(err)
	}

	exited := make(chan struct{})
	go func() { _ = stale.Wait(); close(exited) }()
	h := newHarness(t, st, "run", nil)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("stale frpc not stopped")
	}
	if len(pidsFromLog(staleLog, "exit")) != 1 {
		t.Fatal("stale frpc was not stopped gracefully")
	}
	eventually(t, "new frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
}

func TestStaleRecordForOtherProcessIsIgnored(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	exe, _ := os.Executable()
	prev, err := New(Config{Store: st, FRPCPath: exe, TrustedCAFile: caFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.toml")
	os.WriteFile(other, []byte(fmt.Sprintf("webServer.port = %d\n", freePort(t))), 0o600)
	foreign, _ := startLooseFRPC(t, other)
	if err := prev.recordPID(foreign.Process.Pid); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	eventually(t, "frpc ready", func() bool { s := h.status(); return s.Running && len(s.Proxies) > 0 })
	if !procAlive(foreign.Process.Pid) {
		t.Fatal("a process with a different command line was killed")
	}
	if _, err := os.Stat(filepath.Join(st.Dir(), PIDFile)); err != nil {
		t.Fatal("current frpc pid not recorded")
	}
}
