package forwarder

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/seawise/client/internal/targetpolicy"
)

func lineTrip(t *testing.T, u *Upstream, msg string) string {
	t.Helper()
	_ = u.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(u, msg+"\n"); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(u).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDialThroughPolicy(t *testing.T) {
	port, accepts := echoServer(t)
	f := newFwd(t, Config{})
	f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1"}}})
	u, err := f.Dial(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if got := lineTrip(t, u, "hi"); got != "echo:hi\n" || accepts.Load() != 1 {
		t.Fatalf("%q", got)
	}
	if u.Target() != u.RemoteAddr().String() || u.Configured() != "127.0.0.1:"+itoa(port) {
		t.Fatal(u.Target(), u.Configured())
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func TestDialUnknownApp(t *testing.T) {
	f := newFwd(t, Config{})
	if _, err := f.Dial(context.Background(), "nope"); !errors.Is(err, ErrNoApp) {
		t.Fatal(err)
	}
}

func TestDialRefusedByPolicy(t *testing.T) {
	f := newFwd(t, Config{DialTimeout: time.Second})
	f.Sync([]App{{ID: "m", Host: "169.254.169.254", Port: 80, Rule: targetpolicy.Rule{Host: "169.254.169.254"}}})
	if _, err := f.Dial(context.Background(), "m"); !errors.Is(err, targetpolicy.ErrRefused) {
		t.Fatal(err)
	}
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil
	}
	g := newFwd(t, Config{DialTimeout: time.Second, Resolve: resolve})
	g.Sync([]App{{ID: "z", Host: "zero.test", Port: 80, Rule: targetpolicy.Rule{Host: "zero.test"}}})
	if _, err := g.Dial(context.Background(), "z"); !errors.Is(err, targetpolicy.ErrRefused) {
		t.Fatal("a name resolving to 0.0.0.0 must stay refused:", err)
	}
}

func TestDialUnreachable(t *testing.T) {
	f := newFwd(t, Config{DialTimeout: time.Second})
	f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: closedPort(t), Rule: targetpolicy.Rule{Host: "127.0.0.1"}}})
	_, err := f.Dial(context.Background(), "a")
	if err == nil || errors.Is(err, ErrNoApp) || errors.Is(err, ErrBusy) || errors.Is(err, targetpolicy.ErrRefused) {
		t.Fatal(err)
	}
}

func TestDialSharesTheAppCap(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{MaxConns: 1})
	ports := f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1"}}})
	u, err := f.Dial(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Dial(context.Background(), "a"); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	c := dialApp(t, ports["a"])
	if _, err := roundTrip(c, "x"); err == nil {
		t.Fatal("listener connection over the shared cap forwarded")
	}
	c.Close()
	_ = u.Close()
	_ = u.Close()
	u2, err := f.Dial(context.Background(), "a")
	if err != nil {
		t.Fatal("slot not released once:", err)
	}
	u2.Close()
	u3, err := f.Dial(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	u3.Close()
}

func TestDialFailureReleasesSlot(t *testing.T) {
	f := newFwd(t, Config{MaxConns: 1, DialTimeout: time.Second})
	f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: closedPort(t), Rule: targetpolicy.Rule{Host: "127.0.0.1"}}})
	for range 3 {
		if _, err := f.Dial(context.Background(), "a"); err == nil || errors.Is(err, ErrBusy) {
			t.Fatal(err)
		}
	}
}

func TestSyncClosesUpstreams(t *testing.T) {
	port, _ := echoServer(t)
	f := newFwd(t, Config{})
	app := App{ID: "a", Host: "127.0.0.1", Port: port, Rule: targetpolicy.Rule{Host: "127.0.0.1"}}
	f.Sync([]App{app})
	u, err := f.Dial(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = lineTrip(t, u, "one")
	f.Sync(nil)
	_ = u.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := u.Read(make([]byte, 1)); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("upstream survived Sync(nil):", err)
	}
	if _, err := f.Dial(context.Background(), "a"); !errors.Is(err, ErrNoApp) {
		t.Fatal(err)
	}
}

func TestDialThisMachineTarget(t *testing.T) {
	port, accepts := echoServer(t)
	f := newFwd(t, Config{})
	f.Sync([]App{{ID: "z", Host: "0.0.0.0", Port: port, Rule: targetpolicy.Rule{Host: "0.0.0.0"}}})
	u, err := f.Dial(context.Background(), "z")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if got := lineTrip(t, u, "hi"); got != "echo:hi\n" || accepts.Load() != 1 {
		t.Fatalf("%q", got)
	}
	if u.Target() != "127.0.0.1:"+itoa(port) {
		t.Fatal(u.Target())
	}
}

func TestDialCancelled(t *testing.T) {
	f := newFwd(t, Config{})
	f.Sync([]App{{ID: "a", Host: "127.0.0.1", Port: closedPort(t), Rule: targetpolicy.Rule{Host: "127.0.0.1"}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Dial(ctx, "a"); err == nil {
		t.Fatal("dial with a cancelled context")
	}
}
