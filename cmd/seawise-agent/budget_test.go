package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/tufrepo"
)

// Memory budgets for the agent process, measured on the release build.
const (
	idleBudgetKiB = 30 << 10
	busyBudgetKiB = 96 << 10

	budgetApps     = 4
	connsPerApp    = 48
	busyDuration   = 5 * time.Second
	settleDuration = 3 * time.Second
)

const budgetServerID = "11111111-2222-4333-8444-555555555555"

// TestMemoryBudget builds seawise-agent without the race detector, runs it
// with a stand-in frpc, a fake control plane and a local signed update
// repository, and checks resident memory when idle (after a verified update
// check) and while forwarding many connections.
func TestMemoryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the agent")
	}
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	// The gate must not pass silently: without a toolchain to build the
	// agent, the test fails. Use -short to leave it out on purpose.
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("Go toolchain needed to build the agent for the memory budget: %v", err)
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "seawise-agent")
	build := exec.Command(goBin, "build", "-trimpath", "-tags", "seawise_tuftest", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	frpc := filepath.Join(tmp, "frpc")
	if err := os.WriteFile(frpc, []byte("#!/bin/sh\nexec sleep 3600\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(ca, []byte("placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	echoPort := echoTarget(t)
	api := fakeControlPlane(t)
	dataDir := filepath.Join(tmp, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pairedDataDir(t, dataDir, api.URL, echoPort)
	tufDir := updateRepo(t)

	cmd := exec.Command(bin)
	cmd.Env = []string{
		"SEAWISE_DATA_DIR=" + dataDir,
		"SEAWISE_FRPC_PATH=" + frpc,
		"SEAWISE_TRUSTED_CA_FILE=" + ca,
		"SEAWISE_PORT=" + strconv.Itoa(freePort(t)),
		"SEAWISE_BIND_ADDR=127.0.0.1",
		"PATH=/usr/bin:/bin",
		// Keep DNS lookups of the tunnel server off the network.
		"HTTPS_PROXY=http://127.0.0.1:9",
		"NO_PROXY=127.0.0.1,localhost",
		"SEAWISE_TEST_TUF_DIR=" + tufDir,
	}
	var stderr strings.Builder
	cmd.Stderr = &lockedWriter{w: &stderr}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("agent log:\n%s", stderr.String())
		}
	}()

	ports := waitForwarderPorts(t, filepath.Join(dataDir, store.SubDir, "frpc.toml"), budgetApps)
	waitFile(t, filepath.Join(dataDir, store.SubDir, "tuf", "state.json"))
	time.Sleep(settleDuration)
	idle := maxRSS(t, cmd.Process.Pid, 2*time.Second)

	moved := drive(t, ports, connsPerApp, busyDuration)
	peak := procKiB(t, cmd.Process.Pid, "VmHWM")
	t.Logf("idle RSS %.1f MiB (budget %d MiB); busy peak RSS %.1f MiB (budget %d MiB) with %d connections moving %.0f MiB",
		float64(idle)/1024, idleBudgetKiB>>10, float64(peak)/1024, busyBudgetKiB>>10, budgetApps*connsPerApp, float64(moved)/(1<<20))
	if idle > idleBudgetKiB {
		t.Errorf("idle RSS %d KiB over budget %d KiB", idle, idleBudgetKiB)
	}
	if peak > busyBudgetKiB {
		t.Errorf("busy RSS %d KiB over budget %d KiB", peak, busyBudgetKiB)
	}
	if moved == 0 {
		t.Error("no data moved through the forwarder")
	}
}

// updateRepo serves a signed test update repository over HTTPS and returns
// the folder the seawise_tuftest build reads its root, URL and CA from.
func updateRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	now := time.Now()
	keys, err := tufrepo.InitTest(repo, now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := `{"channel":"stable","image":"ghcr.io/seawise-io/seawise-client","version":"9.0.0","digest":"sha256:` + strings.Repeat("a", 64) + `","expires":"` + now.Add(24*time.Hour).UTC().Format(time.RFC3339) + `"}`
	if _, err := tufrepo.SignTargets(repo, keys.Targets, map[string][]byte{"release/stable.json": []byte(manifest), "keyset.json": []byte(`{"keys":[]}`)}, nil, now, tufrepo.DefaultTargetsExpiry); err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(repo, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tufrepo.Refresh(repo, root, keys.Snapshot, keys.Timestamp, now, tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.FileServer(http.Dir(repo)))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	for name, b := range map[string][]byte{"root.json": root, "url": []byte(srv.URL), "ca.pem": ca} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s not written: no verified update check", path)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
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

func echoTarget(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func fakeControlPlane(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/heartbeat"):
			fmt.Fprint(w, `{"data":{"status":"ok","server_status":"online","next_heartbeat_ms":30000}}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/services"):
			var items []string
			for i := 1; i <= budgetApps; i++ {
				items = append(items, fmt.Sprintf(`{"id":"%s","name":"app%d","host":"127.0.0.1","port":1,"subdomain":"app%d","status":"online"}`, serviceID(i), i, i))
			}
			fmt.Fprintf(w, `{"data":[%s]}`, strings.Join(items, ","))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func serviceID(i int) string { return fmt.Sprintf("aaaaaaaa-0000-4000-8000-%012d", i) }

func pairedDataDir(t *testing.T, dir, apiURL string, port int) {
	t.Helper()
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "synthetic-token"; return nil }); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: budgetServerID, FRPServerAddr: "frp-1.seawise.dev", FRPServerPort: 7000, APIURL: apiURL}
		for i := 1; i <= budgetApps; i++ {
			s.Targets = append(s.Targets, store.Target{
				LocalID: fmt.Sprintf("app%d", i), Name: fmt.Sprintf("app%d", i), Host: "127.0.0.1", Port: port,
				ServerServiceID: serviceID(i), Subdomain: fmt.Sprintf("app%d", i), Source: store.SourceLocal,
				ConfirmedAt: &now, Allowed: []string{"loopback"},
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func waitForwarderPorts(t *testing.T, conf string, n int) []int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var ports []int
		if b, err := os.ReadFile(conf); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(line, "localPort = "); ok {
					if p, err := strconv.Atoi(v); err == nil {
						ports = append(ports, p)
					}
				}
			}
		}
		if len(ports) == n {
			return ports
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("agent did not render %d forwarders", n)
	return nil
}

// drive streams data through every forwarder port and returns the bytes
// echoed back.
func drive(t *testing.T, ports []int, perPort int, d time.Duration) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var moved atomic.Int64
	var wg sync.WaitGroup
	for _, p := range ports {
		for i := 0; i < perPort; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 5*time.Second)
				if err != nil {
					return
				}
				defer c.Close()
				go func() { <-ctx.Done(); c.Close() }()
				buf := make([]byte, 32<<10)
				go func() {
					for ctx.Err() == nil {
						if _, err := c.Write(buf); err != nil {
							return
						}
					}
				}()
				rb := make([]byte, 32<<10)
				for {
					n, err := c.Read(rb)
					moved.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	return moved.Load()
}

func maxRSS(t *testing.T, pid int, over time.Duration) int64 {
	t.Helper()
	var peak int64
	for end := time.Now().Add(over); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		peak = max(peak, procKiB(t, pid, "VmRSS"))
	}
	return peak
}

func procKiB(t *testing.T, pid int, field string) int64 {
	t.Helper()
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), field+":"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatalf("%s not in /proc/%d/status", field, pid)
	return 0
}
