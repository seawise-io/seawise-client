package main

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/caps"

	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/healthprobe"
	"github.com/seawise/client/internal/testedge"
)

// Budgets for an idle agent with its tunnel session up, on either
// carriage: resident memory, and control traffic on the wire per 30-day
// month (decimal megabytes).
const (
	tunnelIdleBudgetKiB  = 24 << 10
	monthlyTrafficBudget = 50_000_000

	budgetMonth = 30 * 24 * time.Hour
	// pingAfter is the ping interval the edge sends in HelloAck.
	pingAfter = 20 * time.Second
	// sessionEvery is the shortest session lifetime the edge sets
	// (max_session_age_s is 12-24 h); each new session pays its start.
	sessionEvery  = 12 * time.Hour
	burstGap      = 300 * time.Millisecond
	tunnelApps    = 10
	measureFor    = 130 * time.Second
	testListEvery = 40 * time.Second
	tunnelServer  = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
)

// TestTunnelIdleBudget runs the release build of the agent against a
// protocol-level edge on each carriage and checks idle memory and the
// monthly control traffic priced from what went over the socket.
func TestTunnelIdleBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the agent")
	}
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc and TCP_INFO")
	}
	bin := buildAgent(t, t.TempDir())
	for _, carriage := range []string{"tls", "websocket"} {
		t.Run(carriage, func(t *testing.T) {
			t.Parallel()
			idleBudget(t, bin, carriage)
		})
	}
}

// toggled is a TCP target that can be switched off and on.
type toggled struct {
	addr string
	ln   atomic.Pointer[net.Listener]
}

func newToggled(t *testing.T) *toggled {
	t.Helper()
	tg := &toggled{}
	tg.on(t, "127.0.0.1:0")
	t.Cleanup(func() { tg.off() })
	return tg
}

func (tg *toggled) on(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tg.addr = ln.Addr().String()
	tg.ln.Store(&ln)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
}

func (tg *toggled) off() {
	if l := tg.ln.Swap(nil); l != nil {
		_ = (*l).Close()
	}
}

func (tg *toggled) port() int {
	_, p, _ := net.SplitHostPort(tg.addr)
	n, _ := strconv.Atoi(p)
	return n
}

func idleBudget(t *testing.T, bin, carriage string) {
	tmp := t.TempDir()
	ca, err := testedge.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	keys := testedge.NewKeys("budget", "edge-us-east-0")
	flip := newToggled(t)
	apps := testedge.TestApps(tunnelApps, "127.0.0.1", echoTarget(t))
	apps[0].Port = flip.port()

	var device atomic.Pointer[ed25519.PublicKey]
	edge, err := testedge.New(testedge.Config{Keys: keys, CA: ca, ServerID: tunnelServer, TunnelName: defaultTunnelName,
		APIHost: "127.0.0.1", Apps: apps, DeviceKey: func() ed25519.PublicKey {
			if p := device.Load(); p != nil {
				return *p
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	// TCP keepalive off on the edge side too (spec: liveness is the
	// stream 0 ping); Go's default would probe every 15 s of quiet.
	lc := net.ListenConfig{KeepAlive: -1}
	tunnelLn, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnelLn.Close() })
	go func() { _ = edge.ServeTunnel(tunnelLn) }()
	if carriage == "websocket" {
		edge.BlockRawTLS(true)
	}

	repo := filepath.Join(tmp, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	tufLn := testedge.Count(listen(t))
	tufSrv := &http.Server{Handler: http.FileServer(http.Dir(repo)), TLSConfig: edge.APITLS(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = tufSrv.ServeTLS(tufLn, "", "") }()
	t.Cleanup(func() { _ = tufSrv.Close() })
	apiLn := listen(t)
	apiSrv := &http.Server{Handler: edge.APIHandler(nil), TLSConfig: edge.APITLS(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = apiSrv.ServeTLS(apiLn, "", "") }()
	t.Cleanup(func() { _ = apiSrv.Close() })

	tufDir := filepath.Join(tmp, "tuf")
	dataDir := filepath.Join(tmp, "data")
	for _, d := range []string{tufDir, dataDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := testedge.UpdateRepo(repo, tufDir, "https://"+tufLn.Addr().String(), keys, ca, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, err := testedge.PairedDataDir(dataDir, tunnelServer, "https://"+apiLn.Addr().String(), apps)
	if err != nil {
		t.Fatal(err)
	}
	device.Store(&pub)
	caFile := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin)
	cmd.Env = []string{
		"SEAWISE_DATA_DIR=" + dataDir,
		"SEAWISE_PORT=" + strconv.Itoa(freePort(t)),
		"SEAWISE_BIND_ADDR=127.0.0.1",
		"PATH=/usr/bin:/bin",
		"SSL_CERT_FILE=" + caFile,
		"SSL_CERT_DIR=" + filepath.Join(tmp, "no-certs"),
		"SEAWISE_TEST_TUF_DIR=" + tufDir,
		"SEAWISE_TEST_EDGE_ADDR=" + tunnelLn.Addr().String(),
		"SEAWISE_TEST_LIST_EVERY=" + testListEvery.String(),
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
	pid := cmd.Process.Pid

	// Up on the expected carriage, and the fresh health rounds done.
	var sess *testedge.Session
	waitFor(t, 90*time.Second, "session up on "+carriage, func() bool {
		if l := edge.Live(); len(l) > 0 {
			sess = l[0]
		}
		return sess != nil
	})
	if sess.Carriage != carriage {
		t.Fatalf("session on %s, want %s", sess.Carriage, carriage)
	}
	waitFor(t, 90*time.Second, "fresh health rounds over stream 0", func() bool {
		return edge.Calls()["stream0:REPORT_HEALTH"] >= healthprobe.FreshRounds
	})
	time.Sleep(3 * time.Second)

	from := time.Now()
	calls0 := edge.Calls()
	var rss int64
	sample := func(until time.Time) {
		for time.Now().Before(until) {
			rss = max(rss, procKiB(t, pid, "VmRSS"))
			time.Sleep(500 * time.Millisecond)
		}
	}
	// One app goes down and comes back: two health changes to price.
	sample(from.Add(5 * time.Second))
	flip.off()
	sample(from.Add(65 * time.Second))
	flip.on(t, flip.addr)
	sample(from.Add(measureFor))
	to := time.Now()
	calls1 := edge.Calls()

	if l := edge.Live(); len(l) != 1 || l[0] != sess {
		t.Fatalf("session did not stay up: %d live", len(l))
	}
	if kids := children(pid); kids != "" {
		t.Fatalf("agent has child processes: %s", kids)
	}
	health := calls1["stream0:REPORT_HEALTH"] - calls0["stream0:REPORT_HEALTH"]
	if health > 2 {
		t.Errorf("%d health reports in %v with two changes: unchanged reports are sent", health, measureFor)
	}
	for k, v := range calls1 {
		if strings.HasPrefix(k, "https:") && v != calls0[k] {
			t.Errorf("%s sent over HTTPS while the session was up", k)
		}
	}

	all := sess.Bursts(time.Time{}, to, burstGap)
	var window []testedge.Burst
	for _, b := range all {
		if !b.Start.Before(from) {
			window = append(window, b)
		}
	}
	cost := priceBursts(t, all, window)
	update := tufLn.Wire()
	total, lines := monthly(cost, update)

	t.Logf("%s: idle RSS %.1f MiB (budget %d MiB)", carriage, float64(rss)/1024, tunnelIdleBudgetKiB>>10)
	for _, b := range window {
		t.Logf("%s: burst %-24s %6d B %3d segments %v", carriage, b.Kind(), b.Bytes, b.Segments, b.Kinds)
	}
	for _, l := range lines {
		t.Logf("%s: %s", carriage, l)
	}
	t.Logf("%s: monthly control traffic %.1f MB (budget %d MB)", carriage, float64(total)/1e6, monthlyTrafficBudget/1_000_000)
	if rss > tunnelIdleBudgetKiB {
		t.Errorf("idle RSS %d KiB over budget %d KiB", rss, tunnelIdleBudgetKiB)
	}
	if total > monthlyTrafficBudget {
		t.Errorf("monthly control traffic %d B over budget %d B", total, monthlyTrafficBudget)
	}
}

// burstCost is the measured wire cost of each kind of idle activity.
type burstCost struct {
	start, ping, health, list, rtt int64
	rttMeasured                    bool
}

// priceBursts takes the median of each kind. A burst holding one device
// call and pings is priced as the call after the pings' median.
func priceBursts(t *testing.T, all, window []testedge.Burst) burstCost {
	t.Helper()
	var c burstCost
	var n int
	if c.start, n = testedge.Median(all, "start"); n != 1 {
		t.Fatalf("%d session starts on one connection", n)
	}
	// The TCP handshake before the first sample and the close.
	c.start += 7 * testedge.TCPHeader
	if c.ping, n = testedge.Median(window, "ping"); n < 2 {
		t.Fatalf("only %d ping bursts measured", n)
	}
	call := func(method string) int64 {
		kind := "call:" + method
		var v []int64
		for _, b := range window {
			switch b.Kind() {
			case kind:
				v = append(v, b.Bytes)
			case "mixed":
				pings, calls := 0, 0
				for _, k := range b.Kinds {
					switch k {
					case "ping":
						pings++
					case kind:
						calls++
					default:
						if strings.HasPrefix(k, "call:") {
							calls += 2
						}
					}
				}
				if calls == 1 {
					v = append(v, b.Bytes-int64(pings)*c.ping)
				}
			}
		}
		if len(v) == 0 {
			t.Fatalf("no %s measured", kind)
		}
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		return v[len(v)/2]
	}
	c.health = call("REPORT_HEALTH")
	c.list = call("LIST_APPS")
	// go-yamux's RTT ping runs every 10 minutes; when none fell in the
	// window it is priced as a stream 0 ping, which is larger.
	if c.rtt, n = testedge.Median(window, "transport"); n == 0 {
		c.rtt = c.ping
	} else {
		c.rttMeasured = true
	}
	return c
}

// monthly prices 30 days of idle time at the agent's own cadences: a
// health refresh, the app list, go-yamux's RTT ping, a new session every
// sessionEvery, a stream 0 ping whenever pingAfter passes with nothing
// received, and one full update check a day.
func monthly(c burstCost, update int64) (int64, []string) {
	type cadence struct {
		name   string
		every  time.Duration
		offset time.Duration
		cost   int64
	}
	plan := []cadence{
		{"health refresh", appsync.HealthRefresh, 7 * time.Second, c.health},
		{"app list", appsync.DefaultListEvery, 13 * time.Second, c.list},
		{"yamux RTT ping", caps.MeasureRTTInterval, 3 * time.Second, c.rtt},
		{"session start", sessionEvery, 0, c.start},
	}
	var at []time.Duration
	count := map[string]int64{}
	var total int64
	for _, p := range plan {
		for d := p.offset; d < budgetMonth; d += p.every {
			at = append(at, d)
			count[p.name]++
		}
		total += count[p.name] * p.cost
	}
	slices.Sort(at)
	at = append(at, budgetMonth)
	var pings int64
	last := time.Duration(0)
	for _, d := range at {
		for d-last > pingAfter {
			last += pingAfter
			pings++
		}
		last = d
	}
	total += pings*c.ping + 30*update
	lines := []string{fmt.Sprintf("per burst: start %d B, ping %d B, health %d B, list %d B, yamux RTT %d B (measured %v), update check %d B",
		c.start, c.ping, c.health, c.list, c.rtt, c.rttMeasured, update)}
	for _, p := range plan {
		lines = append(lines, fmt.Sprintf("month: %-15s %7d x %6d B = %6.2f MB", p.name, count[p.name], p.cost, float64(count[p.name]*p.cost)/1e6))
	}
	lines = append(lines, fmt.Sprintf("month: %-15s %7d x %6d B = %6.2f MB", "ping", pings, c.ping, float64(pings*c.ping)/1e6),
		fmt.Sprintf("month: %-15s %7d x %6d B = %6.2f MB", "update check", 30, update, float64(30*update)/1e6))
	// An edge with TCP keepalive on (Go's default: a probe after 15 s of
	// quiet) adds a bare probe and its ACK in each quiet spell.
	lines = append(lines, fmt.Sprintf("for comparison, edge TCP keepalive at 15 s: %.1f MB more", float64(pings*2*testedge.TCPHeader)/1e6))
	// What the unchanged report every probe round would add.
	every := int64(budgetMonth / healthprobe.DefaultInterval)
	lines = append(lines, fmt.Sprintf("for comparison, a health report every %v: %.1f MB more", healthprobe.DefaultInterval,
		float64((every-count["health refresh"])*c.health)/1e6))
	return total, lines
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// children lists the child processes of pid.
func children(pid int) string {
	tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	var out []string
	for _, task := range tasks {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", pid, task.Name()))
		if s := strings.TrimSpace(string(b)); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}
