package forwarder

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/targetpolicy"
)

// echoServer replies to each line with "echo:<line>" and counts accepts.
func echoServer(t *testing.T) (port int, accepts *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepts = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := io.WriteString(c, "echo:"+line); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepts
}

func newFwd(t *testing.T, cfg Config) *Forwarder {
	t.Helper()
	if cfg.Resolve == nil {
		cfg.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no DNS in tests") }
	}
	f := New(cfg)
	t.Cleanup(f.Close)
	return f
}

func dialApp(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func roundTrip(c net.Conn, msg string) (string, error) {
	if _, err := io.WriteString(c, msg+"\n"); err != nil {
		return "", err
	}
	return bufio.NewReader(c).ReadString('\n')
}

// refused asserts the proxy closes the connection without forwarding.
func refused(t *testing.T, f *Forwarder, app App) {
	t.Helper()
	ports := f.Sync([]App{app})
	port, ok := ports[app.ID]
	if !ok {
		t.Fatalf("%s: no listener", app.ID)
	}
	c := dialApp(t, port)
	defer c.Close()
	if got, err := roundTrip(c, "hi"); err == nil {
		t.Fatalf("%s: forwarded, got %q", app.ID, got)
	}
}

func TestForwardsAllowedTarget(t *testing.T) {
	port, accepts := echoServer(t)
	f := newFwd(t, Config{})
	app := App{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1", Grants: []string{targetpolicy.GrantLoopback}}}
	ports := f.Sync([]App{app})
	c := dialApp(t, ports["a"])
	defer c.Close()
	got, err := roundTrip(c, "hello")
	if err != nil || got != "echo:hello\n" || accepts.Load() != 1 {
		t.Fatalf("forward: %q %v", got, err)
	}
	if again := f.Sync([]App{app}); again["a"] != ports["a"] {
		t.Fatal("unchanged app got a new listener")
	}
}

func TestRefusesForbiddenAndUngranted(t *testing.T) {
	f := newFwd(t, Config{DialTimeout: time.Second})
	refused(t, f, App{ID: "meta", Host: "169.254.169.254", Port: 80, Rule: targetpolicy.Rule{Host: "169.254.169.254", Grandfathered: true}})
	refused(t, f, App{ID: "ll", Host: "169.254.10.10", Port: 80, Rule: targetpolicy.Rule{Host: "169.254.10.10", Grandfathered: true}})
	refused(t, f, App{ID: "pub", Host: "93.184.216.34", Port: 80, Rule: targetpolicy.Rule{Host: "93.184.216.34"}})
	refused(t, f, App{ID: "nat64", Host: "64:ff9b::a9fe:a9fe", Port: 80, Rule: targetpolicy.Rule{Host: "64:ff9b::a9fe:a9fe", Grandfathered: true}})
}

func TestRebindingToLoopbackRefused(t *testing.T) {
	port, accepts := echoServer(t)
	resolve := func(_ context.Context, h string) ([]netip.Addr, error) {
		if h == "rebind.test" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	f := newFwd(t, Config{Resolve: resolve})
	all := []string{targetpolicy.GrantLoopback, targetpolicy.GrantPublic, targetpolicy.GrantSensitive, targetpolicy.GrantGateway}
	refused(t, f, App{ID: "r", Host: "rebind.test", Port: port, Rule: targetpolicy.Rule{Host: "rebind.test", Grants: all, Grandfathered: true}})
	if accepts.Load() != 0 {
		t.Fatal("target was connected to")
	}
}

func TestRevocationClosesListenerAndConnections(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{})
	granted := App{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1", Grants: []string{targetpolicy.GrantLoopback}}}
	ports := f.Sync([]App{granted})
	c := dialApp(t, ports["a"])
	defer c.Close()
	if _, err := roundTrip(c, "one"); err != nil {
		t.Fatal(err)
	}
	revoked := granted
	revoked.Rule = targetpolicy.Rule{Host: "127.0.0.1"}
	newPorts := f.Sync([]App{revoked})
	if newPorts["a"] == ports["a"] {
		t.Fatal("listener kept after a grant change")
	}
	if _, err := roundTrip(c, "two"); err == nil {
		t.Fatal("open connection survived revocation")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(ports["a"]), time.Second); err == nil {
		t.Fatal("old listener still accepting")
	}
	f.Sync(nil)
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(newPorts["a"]), time.Second); err == nil {
		t.Fatal("removed app still listening")
	}
}

func TestConnectionCap(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{MaxConns: 1})
	ports := f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1", Grants: []string{targetpolicy.GrantLoopback}}}})
	first := dialApp(t, ports["a"])
	defer first.Close()
	if _, err := roundTrip(first, "x"); err != nil {
		t.Fatal(err)
	}
	second := dialApp(t, ports["a"])
	defer second.Close()
	if _, err := roundTrip(second, "y"); err == nil {
		t.Fatal("connection over the cap forwarded")
	}
}

func TestIdleTimeout(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{IdleTimeout: 150 * time.Millisecond})
	ports := f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1", Grants: []string{targetpolicy.GrantLoopback}}}})
	c := dialApp(t, ports["a"])
	defer c.Close()
	if _, err := roundTrip(c, "x"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := roundTrip(c, "y"); err == nil {
		t.Fatal("idle connection not closed")
	}
}

func TestListenersOnLoopbackOnly(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{})
	f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1", Grants: []string{targetpolicy.GrantLoopback}}}})
	for _, l := range f.listeners() {
		if !l.ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
			t.Fatalf("listener on %v", l.ln.Addr())
		}
	}
}

func loopApp(port int) App {
	return App{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1", Grants: []string{targetpolicy.GrantLoopback}}}
}

func TestMaxLifetime(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{MaxLifetime: 300 * time.Millisecond, CheckEvery: 50 * time.Millisecond})
	c := dialApp(t, f.Sync([]App{loopApp(port)})["a"])
	defer c.Close()
	r := bufio.NewReader(c)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := io.WriteString(c, "x\n"); err != nil {
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("busy connection outlived the maximum lifetime")
}

func TestSlowDripClosed(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{MinBytes: 100, CheckEvery: 100 * time.Millisecond})
	c := dialApp(t, f.Sync([]App{loopApp(port)})["a"])
	defer c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte("x")); err != nil {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("slow-drip connection kept its slot")
}

func TestTargetResetClosesClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.(*net.TCPConn).SetLinger(0)
		time.Sleep(50 * time.Millisecond)
		c.Close() // RST
	}()
	f := newFwd(t, Config{})
	c := dialApp(t, f.Sync([]App{loopApp(ln.Addr().(*net.TCPAddr).Port)})["a"])
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client not closed after target reset")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("client left open after target reset")
	}
}
