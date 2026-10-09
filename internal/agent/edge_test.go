package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

type fakeDNS struct {
	mu    sync.Mutex
	addrs []netip.Addr
	err   error
	calls atomic.Int32
}

func (f *fakeDNS) set(err error, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err, f.addrs = err, nil
	for _, a := range addrs {
		f.addrs = append(f.addrs, netip.MustParseAddr(a))
	}
}

func (f *fakeDNS) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addrs, f.err
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var errNoDNS = errors.New("no such host")

func TestProxyRenderedForFRPC(t *testing.T) {
	dns := &fakeDNS{}
	dns.set(nil, "93.184.216.10")
	env := map[string]string{"HTTPS_PROXY": "http://user:pw@proxy.lan:3128"}
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", func(c *Config) { c.Getenv = envOf(env); c.ResolveEdge = dns.resolve })
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if got := confValue(t, h.agent.ConfigPath(), "transport.proxyURL"); got != `"http://user:pw@proxy.lan:3128"` {
		t.Fatalf("proxyURL = %s", got)
	}
	if got := confValue(t, h.agent.ConfigPath(), "serverAddr"); got != `"frp-1.seawise.dev"` {
		t.Fatalf("serverAddr = %s", got)
	}
	if dns.calls.Load() != 0 {
		t.Fatal("resolved the frps host locally although a proxy is set")
	}
}

func TestNoProxyBypassesFRPCProxy(t *testing.T) {
	env := map[string]string{"HTTP_PROXY": "http://proxy.lan:3128", "NO_PROXY": ".seawise.dev"}
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", func(c *Config) { c.Getenv = envOf(env) })
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if got := confValue(t, h.agent.ConfigPath(), "transport.proxyURL"); got != "" {
		t.Fatalf("proxyURL = %s", got)
	}
}

func TestUnsupportedProxySchemeRefused(t *testing.T) {
	env := map[string]string{"HTTPS_PROXY": "https://user:secret@proxy.lan:3128"}
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", func(c *Config) { c.Getenv = envOf(env) })
	if err := h.agent.Reconcile(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	s := h.status()
	if s.Running || h.count("start") != 0 || !strings.Contains(s.LastError, "unsupported proxy scheme") {
		t.Fatalf("status = %+v", s)
	}
	if strings.Contains(s.LastError, "secret") {
		t.Fatal("proxy credentials in the error")
	}
}

func TestFRPCGetsNoEnvironment(t *testing.T) {
	t.Setenv("SEAWISE_ADMIN_PASSWORD", "x")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.invalid:3128")
	if env := childEnv(); len(env) != 0 {
		t.Fatalf("frpc environment = %v", env)
	}
}

func TestEdgeAddressCachedAndUsedWhenDNSFails(t *testing.T) {
	dir := t.TempDir()
	st := pairedStore(t, dir)
	dns := &fakeDNS{}
	dns.set(nil, "2606:4700::10", "93.184.216.10", "127.0.0.1")
	h := newHarness(t, st, "run", func(c *Config) { c.ResolveEdge = dns.resolve })
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if got := confValue(t, h.agent.ConfigPath(), "serverAddr"); got != `"frp-1.seawise.dev"` {
		t.Fatalf("serverAddr with working DNS = %s", got)
	}
	e := st.State().EdgeDNS
	if e == nil || e.Host != "frp-1.seawise.dev" || strings.Join(e.Addrs, ",") != "2606:4700::10,93.184.216.10" {
		t.Fatalf("cache = %+v", e)
	}
	h.stop()

	dns.set(errNoDNS)
	h = newHarness(t, st, "run", func(c *Config) { c.ResolveEdge = dns.resolve })
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if got := confValue(t, h.agent.ConfigPath(), "serverAddr"); got != `"93.184.216.10"` {
		t.Fatalf("fallback serverAddr = %s", got)
	}
	if got := confValue(t, h.agent.ConfigPath(), "transport.tls.serverName"); got != `"frp-1.seawise.dev"` {
		t.Fatalf("TLS server name = %s", got)
	}
	if s := h.status(); s.EdgeFallback != "93.184.216.10" {
		t.Fatalf("status = %+v", s)
	}
}

func TestEdgeCacheExpiresAndIsPerHost(t *testing.T) {
	for name, cache := range map[string]*store.EdgeDNS{
		"expired":    {Host: "frp-1.seawise.dev", Addrs: []string{"93.184.216.10"}, ResolvedAt: time.Now().Add(-EdgeCacheTTL - time.Hour)},
		"other host": {Host: "frp-2.seawise.dev", Addrs: []string{"93.184.216.10"}, ResolvedAt: time.Now()},
	} {
		t.Run(name, func(t *testing.T) {
			st := pairedStore(t, t.TempDir())
			if err := st.Update(func(s *store.State) error { s.EdgeDNS = cache; return nil }); err != nil {
				t.Fatal(err)
			}
			dns := &fakeDNS{}
			dns.set(errNoDNS)
			h := newHarness(t, st, "run", func(c *Config) { c.ResolveEdge = dns.resolve })
			eventually(t, "frpc ready", func() bool { return h.status().Running })
			if got := confValue(t, h.agent.ConfigPath(), "serverAddr"); got != `"frp-1.seawise.dev"` {
				t.Fatalf("serverAddr = %s", got)
			}
		})
	}
}

func TestEdgeCacheIgnoresNonGlobal(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	dns := &fakeDNS{}
	dns.set(nil, "127.0.0.1", "::1", "169.254.1.1", "0.0.0.0", "224.0.0.1",
		"10.0.0.5", "172.16.1.1", "192.168.1.1", "100.64.0.1", "fd00::1", "198.18.0.1", "203.0.113.5", "2001:db8::1", "64:ff9b::a00:1")
	h := newHarness(t, st, "run", func(c *Config) { c.ResolveEdge = dns.resolve })
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if e := st.State().EdgeDNS; e != nil {
		t.Fatalf("cached unusable addresses: %+v", e)
	}
}

func TestEdgeRecheckReturnsToHostname(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	if err := st.Update(func(s *store.State) error {
		s.EdgeDNS = &store.EdgeDNS{Host: "frp-1.seawise.dev", Addrs: []string{"93.184.216.10"}, ResolvedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	dns := &fakeDNS{}
	dns.set(errNoDNS)
	h := newHarness(t, st, "run", func(c *Config) { c.ResolveEdge = dns.resolve; c.EdgeRecheck = 50 * time.Millisecond })
	eventually(t, "fallback", func() bool { return h.status().EdgeFallback != "" })
	dns.set(nil, "93.184.216.11")
	eventually(t, "back on the host name", func() bool {
		s := h.status()
		return s.Running && s.EdgeFallback == "" && confValue(t, h.agent.ConfigPath(), "serverAddr") == `"frp-1.seawise.dev"`
	})
	if _, err := os.Stat(h.agent.ConfigPath()); err != nil {
		t.Fatal(err)
	}
}

func TestEdgeCacheFilteredWhenRead(t *testing.T) {
	for name, cache := range map[string]*store.EdgeDNS{
		"private":  {Host: "frp-1.seawise.dev", Addrs: []string{"10.0.0.5"}, ResolvedAt: time.Now()},
		"cgnat":    {Host: "frp-1.seawise.dev", Addrs: []string{"100.64.1.1"}, ResolvedAt: time.Now()},
		"ula":      {Host: "frp-1.seawise.dev", Addrs: []string{"fd12::1"}, ResolvedAt: time.Now()},
		"future":   {Host: "frp-1.seawise.dev", Addrs: []string{"93.184.216.10"}, ResolvedAt: time.Now().Add(48 * time.Hour)},
		"loopback": {Host: "frp-1.seawise.dev", Addrs: []string{"127.0.0.1"}, ResolvedAt: time.Now()},
	} {
		t.Run(name, func(t *testing.T) {
			st := pairedStore(t, t.TempDir())
			if err := st.Update(func(s *store.State) error { s.EdgeDNS = cache; return nil }); err != nil {
				t.Fatal(err)
			}
			dns := &fakeDNS{}
			dns.set(errNoDNS)
			h := newHarness(t, st, "run", func(c *Config) { c.ResolveEdge = dns.resolve })
			eventually(t, "frpc ready", func() bool { return h.status().Running })
			if got := confValue(t, h.agent.ConfigPath(), "serverAddr"); got != `"frp-1.seawise.dev"` {
				t.Fatalf("serverAddr = %s", got)
			}
		})
	}
}
