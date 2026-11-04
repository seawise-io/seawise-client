package transport

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func dataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeLastKnown(t *testing.T, dir string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(filepath.Join(dir, LastKnownFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dnsDown(c *Config) {
	c.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no DNS") }
}

func TestLastKnownRememberedAndUsed(t *testing.T) {
	e := newEdge(t)
	dir := dataDir(t)
	s, err := e.dialer(t, func(c *Config) {
		c.DataDir = dir
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr(testIP), netip.MustParseAddr("2001:4860:4860::8844")}, nil
		}
		base := c.DialTCP
		c.DialTCP = func(ctx context.Context, n, addr string) (net.Conn, error) {
			if addr == "10.0.0.1:443" {
				return nil, errors.New("unreachable")
			}
			return base(ctx, n, addr)
		}
	}).Dial(ctx(t), testName, TLS)
	if err != nil || s.LastKnown {
		t.Fatal(err)
	}
	_ = s.Close()
	fi, err := os.Stat(filepath.Join(dir, LastKnownFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal(err)
	}
	var f lastKnownFile
	b, _ := os.ReadFile(filepath.Join(dir, LastKnownFile))
	if err := json.Unmarshal(b, &f); err != nil || f.Schema != 1 || len(f.Edges[testName].Addrs) != 2 ||
		f.Edges[testName].Addrs[0] != testIP || f.Edges[testName].Addrs[1] != "2001:4860:4860::8844" {
		t.Fatal(string(b))
	}
	var tried []string
	s, err = e.dialer(t, func(c *Config) {
		c.DataDir = dir
		dnsDown(c)
		base := c.DialTCP
		c.DialTCP = func(ctx context.Context, n, addr string) (net.Conn, error) {
			tried = append(tried, addr)
			return base(ctx, n, addr)
		}
	}).Dial(ctx(t), testName, WebSocket)
	if err != nil || !s.LastKnown {
		t.Fatal(err)
	}
	_ = s.Close()
	if len(tried) != 1 || tried[0] != net.JoinHostPort(testIP, "443") {
		t.Fatal(tried)
	}
}

func TestLastKnownStillChecksCertificate(t *testing.T) {
	e := newEdge(t)
	dir := dataDir(t)
	writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: time.Now()}}})
	e.cert, _ = pki(t, "other.example")
	_, err := e.dialer(t, func(c *Config) { c.DataDir = dir; dnsDown(c) }).Dial(ctx(t), testName, TLS)
	if er := asError(t, err); er.Cause != CauseTLS {
		t.Fatal(err)
	}
}

func TestLastKnownAgeAndShape(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		file any
		ok   bool
	}{
		"fresh":        {lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: now.Add(-LastKnownMaxAge + time.Minute)}}}, true},
		"stale":        {lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: now.Add(-LastKnownMaxAge)}}}, false},
		"future":       {lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: now.Add(10 * time.Minute)}}}, false},
		"other name":   {lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{"tunnel-eu-west.seawise.dev": {Addrs: []string{testIP}, ResolvedAt: now}}}, false},
		"private addr": {lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{"192.168.1.1"}, ResolvedAt: now}}}, false},
		"schema":       {lastKnownFile{Schema: 2, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: now}}}, false},
		"unknown key":  {map[string]any{"schema": 1, "edges": map[string]any{}, "x": 1}, false},
		"not json":     {"garbage", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEdge(t)
			dir := dataDir(t)
			writeLastKnown(t, dir, c.file)
			s, err := e.dialer(t, func(cfg *Config) { cfg.DataDir = dir; dnsDown(cfg) }).Dial(ctx(t), testName, TLS)
			if c.ok != (err == nil) {
				t.Fatal(err)
			}
			if err == nil {
				_ = s.Close()
				return
			}
			if er := asError(t, err); er.Cause != CauseDial || er.Reason != "resolve" {
				t.Fatal(err)
			}
		})
	}
}

func TestLastKnownNotThroughProxy(t *testing.T) {
	e := newEdge(t)
	dir := dataDir(t)
	writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: time.Now()}}})
	p := newProxy(t, e)
	s, err := e.dialer(t, func(c *Config) { c.DataDir = dir }, env(map[string]string{"HTTPS_PROXY": "http://" + p.ln.Addr().String()}), noDirect(t, p)).Dial(ctx(t), testName, TLS)
	if err != nil || s.LastKnown || !s.Proxied {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestLastKnownCaps(t *testing.T) {
	dir := dataDir(t)
	now := time.Now()
	clock := func() time.Time { return now }
	c := newLastKnown(dir, clock, slog.New(slog.DiscardHandler))
	for i := range 10 {
		now = now.Add(time.Minute)
		c.remember(PoolName("r"+string(rune('a'+i))+"-x"), []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("::ffff:8.8.8.8")})
	}
	f := c.load()
	if len(f.Edges) != lastKnownMaxNames {
		t.Fatal(len(f.Edges))
	}
	if _, ok := f.Edges[PoolName("ra-x")]; ok {
		t.Fatal("oldest kept")
	}
	if a := f.Edges[PoolName("rj-x")].Addrs; len(a) != lastKnownMaxAddrs {
		t.Fatal(a)
	}
	// Nothing public: nothing stored.
	c.remember(PoolName("zz-x"), []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if _, ok := c.load().Edges[PoolName("zz-x")]; ok {
		t.Fatal("stored a loopback address")
	}
	// Same set within the hour: not rewritten.
	before, _ := os.Stat(filepath.Join(dir, LastKnownFile))
	time.Sleep(10 * time.Millisecond)
	c.remember(PoolName("rj-x"), []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("8.8.4.4")})
	after, _ := os.Stat(filepath.Join(dir, LastKnownFile))
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("rewritten without a change")
	}
	if newLastKnown("", clock, nil) != nil {
		t.Fatal("cache without a directory")
	}
}

func TestLastKnownIPv4First(t *testing.T) {
	dir := dataDir(t)
	now := time.Now()
	writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{"2001:4860:4860::8844", testIP}, ResolvedAt: now}}})
	c := newLastKnown(dir, func() time.Time { return now }, slog.New(slog.DiscardHandler))
	addrs, ok := c.lookup(testName)
	if !ok || len(addrs) != 2 || addrs[0].String() != testIP {
		t.Fatal(addrs)
	}
}

func TestLastKnownGroupReadableIgnored(t *testing.T) {
	dir := dataDir(t)
	now := time.Now()
	writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: now}}})
	_ = os.Chmod(filepath.Join(dir, LastKnownFile), 0o644)
	c := newLastKnown(dir, func() time.Time { return now }, slog.New(slog.DiscardHandler))
	if _, ok := c.lookup(testName); ok {
		t.Fatal("used a file others can read")
	}
}
