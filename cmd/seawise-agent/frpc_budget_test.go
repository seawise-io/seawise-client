package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
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
)

// Memory budgets for frpc as the agent runs it, measured with the frp
// release pinned in Dockerfile.agent.
const (
	frpcIdleBudgetKiB = 24 << 10
	frpcBusyBudgetKiB = 64 << 10
	// planIdleKiB is the device budget for both processes; logged only.
	planIdleKiB = 30 << 10

	edgeHost     = "frp-1.seawise.dev"
	vhostDomain  = "seawise.dev"
	targetBodyKB = 64
)

// envFRPDir names a folder holding frpc and frps from tools/frp/fetch.sh.
const envFRPDir = "SEAWISE_TEST_FRP_DIR"

// TestFRPCMemoryBudget runs the agent with the real frpc, connected over
// TLS through an HTTP proxy to a real frps on loopback, and checks the
// resident memory of frpc (and the agent) when idle and while visitors
// download through every app.
func TestFRPCMemoryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the agent with frpc and frps")
	}
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	frpDir := os.Getenv(envFRPDir)
	if frpDir == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s must point at frpc and frps in CI (tools/frp/fetch.sh)", envFRPDir)
		}
		t.Skipf("set %s (tools/frp/fetch.sh) to run", envFRPDir)
	}
	frpc, frps := filepath.Join(frpDir, "frpc"), filepath.Join(frpDir, "frps")
	for _, p := range []string{frpc, frps} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}

	tmp := t.TempDir()
	bin := buildAgent(t, tmp)
	ca := writeTLS(t, tmp)
	bindPort, vhostPort := freePort(t), freePort(t)
	startFRPS(t, frps, tmp, bindPort, vhostPort)
	proxy := connectProxy(t, bindPort)
	target := httpTarget(t)
	api := fakeControlPlane(t)
	dataDir := filepath.Join(tmp, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pairedDataDir(t, dataDir, api.URL, target)

	cmd := exec.Command(bin)
	cmd.Env = []string{
		"SEAWISE_DATA_DIR=" + dataDir,
		"SEAWISE_FRPC_PATH=" + frpc,
		"SEAWISE_TRUSTED_CA_FILE=" + ca,
		"SEAWISE_PORT=" + strconv.Itoa(freePort(t)),
		"SEAWISE_BIND_ADDR=127.0.0.1",
		"SEAWISE_UPDATE_CHECK=0",
		"PATH=/usr/bin:/bin",
		"HTTPS_PROXY=http://" + proxy,
		"NO_PROXY=127.0.0.1,localhost",
	}
	var out strings.Builder
	cmd.Stdout = &lockedWriter{w: &out}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("agent and frpc output:\n%s", out.String())
		}
	}()

	visitor := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(vhostPort))
			},
			MaxIdleConnsPerHost: connsPerApp,
			DisableCompression:  true,
		},
	}
	waitApps(t, visitor)
	time.Sleep(settleDuration)
	frpcPID := childPID(t, cmd.Process.Pid)
	waitApps(t, visitor)
	frpcIdle := maxRSS(t, frpcPID, 2*time.Second)
	agentIdle := procKiB(t, cmd.Process.Pid, "VmRSS")

	moved := visit(t, visitor, connsPerApp, busyDuration)
	frpcPeak := procKiB(t, frpcPID, "VmHWM")
	if now := childPID(t, cmd.Process.Pid); now != frpcPID {
		t.Fatalf("frpc restarted during the measurement (pid %d, then %d)", frpcPID, now)
	}
	agentPeak := procKiB(t, cmd.Process.Pid, "VmHWM")
	t.Logf("frpc idle RSS %.1f MiB (budget %d MiB), busy peak %.1f MiB (budget %d MiB); agent idle %.1f MiB, busy peak %.1f MiB; both idle %.1f MiB (device budget %d MiB); %d visitors moved %.0f MiB",
		mib(frpcIdle), frpcIdleBudgetKiB>>10, mib(frpcPeak), frpcBusyBudgetKiB>>10, mib(agentIdle), mib(agentPeak),
		mib(frpcIdle+agentIdle), planIdleKiB>>10, budgetApps*connsPerApp, float64(moved)/(1<<20))
	if frpcIdle > frpcIdleBudgetKiB {
		t.Errorf("frpc idle RSS %d KiB over budget %d KiB", frpcIdle, frpcIdleBudgetKiB)
	}
	if frpcPeak > frpcBusyBudgetKiB {
		t.Errorf("frpc busy RSS %d KiB over budget %d KiB", frpcPeak, frpcBusyBudgetKiB)
	}
	if agentIdle > idleBudgetKiB || agentPeak > busyBudgetKiB {
		t.Errorf("agent RSS idle %d KiB, busy %d KiB over budget %d/%d KiB", agentIdle, agentPeak, idleBudgetKiB, busyBudgetKiB)
	}
	if moved == 0 {
		t.Error("no data reached the visitors")
	}
}

func mib(kib int64) float64 { return float64(kib) / 1024 }

// writeTLS writes a CA and a certificate for the tunnel server host, and
// returns the CA file the agent hands to frpc.
func writeTLS(t *testing.T, dir string) string {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "budget test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: edgeHost}, DNSNames: []string{edgeHost},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"ca.pem":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"frps.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		"frps.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "ca.pem")
}

func startFRPS(t *testing.T, frps, dir string, bindPort, vhostPort int) {
	t.Helper()
	conf := filepath.Join(dir, "frps.toml")
	body := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = %d
subDomainHost = %q
transport.tls.force = true
transport.tls.certFile = %q
transport.tls.keyFile = %q
log.to = "console"
log.level = "warn"
`, bindPort, vhostPort, vhostDomain, filepath.Join(dir, "frps.crt"), filepath.Join(dir, "frps.key"))
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(frps, "-c", conf)
	cmd.Env = []string{}
	var out strings.Builder
	cmd.Stdout = &lockedWriter{w: &out}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("frps output:\n%s", out.String())
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(bindPort)); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("frps did not start")
}

// connectProxy is an HTTP CONNECT proxy that sends every tunnel to the
// local frps, whatever host frpc asks for.
func connectProxy(t *testing.T, frpsPort int) string {
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
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect || req.Host != edgeHost+":7000" {
					fmt.Fprint(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return
				}
				up, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(frpsPort))
				if err != nil {
					fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer up.Close()
				fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(up, br); up.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func httpTarget(t *testing.T) int {
	t.Helper()
	body := make([]byte, targetBodyKB<<10)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func appURL(i int) string { return fmt.Sprintf("http://app%d.%s/", i, vhostDomain) }

func waitApps(t *testing.T, c *http.Client) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for i := 1; i <= budgetApps; i++ {
		for {
			resp, err := c.Get(appURL(i))
			if err == nil {
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK && n == targetBodyKB<<10 {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("app%d not reachable through frps: %v", i, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// childPID waits until the agent has exactly one child process, frpc.
func childPID(t *testing.T, pid int) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		// Children are listed per thread that started them.
		tasks, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
		if err != nil {
			t.Fatal(err)
		}
		var f []string
		for _, task := range tasks {
			b, _ := os.ReadFile(task)
			f = append(f, strings.Fields(string(b))...)
		}
		if len(f) == 1 {
			child, err := strconv.Atoi(f[0])
			if err != nil {
				t.Fatal(err)
			}
			return child
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent children = %q, want only frpc", f)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// visit downloads from every app with perApp concurrent visitors for d
// and returns the bytes received.
func visit(t *testing.T, c *http.Client, perApp int, d time.Duration) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var moved atomic.Int64
	var wg sync.WaitGroup
	for i := 1; i <= budgetApps; i++ {
		for j := 0; j < perApp; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ctx.Err() == nil {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, appURL(i), nil)
					if err != nil {
						return
					}
					resp, err := c.Do(req)
					if err != nil {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					n, _ := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					moved.Add(n)
				}
			}()
		}
	}
	wg.Wait()
	return moved.Load()
}
