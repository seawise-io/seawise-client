package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

// A spoofed DNS answer that reaches some host but never a verified edge
// must not replace the stored addresses.
func TestLastKnownNotWrittenBeforeHelloAck(t *testing.T) {
	e := newEdge(t)
	dir := dataDir(t)
	stored := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: stored}}})
	before, _ := os.ReadFile(filepath.Join(dir, LastKnownFile))
	spoof, _ := pki(t, "attacker.example")
	impostor := newEdge(t)
	impostor.cert = spoof
	impostor.start()
	_, err := e.dialer(t, func(c *Config) {
		c.DataDir = dir
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
		}
		c.DialTCP = func(ctx context.Context, n, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, n, impostor.ln.Addr().String())
		}
	}).Dial(ctx(t), testName, TLS)
	if er := asError(t, err); er.Cause != CauseTLS {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, LastKnownFile))
	if string(before) != string(after) {
		t.Fatalf("stored addresses changed: %s", after)
	}
	// An edge that answers TLS but fails HelloAck: unchanged as well.
	e.setAnswer(func([32]byte, *pb.Hello) *pb.ControlMessage { return nil })
	_, err = e.dialer(t, func(c *Config) {
		c.DataDir = dir
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
		}
		base := c.DialTCP
		c.DialTCP = func(ctx context.Context, n, _ string) (net.Conn, error) {
			return base(ctx, n, net.JoinHostPort(testIP, edgePort))
		}
	}).Dial(ctx(t), testName, TLS)
	if er := asError(t, err); er.Cause != CauseAckSignature {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, LastKnownFile)); string(before) != string(after) {
		t.Fatalf("stored addresses changed: %s", after)
	}
}

// The carrying address comes first; others from the same lookup follow.
func TestLastKnownStoresCarryingAddressFirst(t *testing.T) {
	e := newEdge(t)
	dir := dataDir(t)
	s, err := e.dialer(t, func(c *Config) {
		c.DataDir = dir
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr(testIP)}, nil
		}
		base := c.DialTCP
		c.DialTCP = func(ctx context.Context, n, a string) (net.Conn, error) {
			if a == "9.9.9.9:443" {
				return nil, errors.New("unreachable")
			}
			return base(ctx, n, a)
		}
	}).Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	var f lastKnownFile
	b, _ := os.ReadFile(filepath.Join(dir, LastKnownFile))
	_ = json.Unmarshal(b, &f)
	if a := f.Edges[testName].Addrs; len(a) != 2 || a[0] != testIP || a[1] != "9.9.9.9" {
		t.Fatal(a)
	}
	_ = protocol.RoleEdge
}

func TestHelloGuard(t *testing.T) {
	var closed atomic.Int32
	g := newHelloGuard(func() { closed.Add(1) })
	g.fire()
	if g.finish() || closed.Load() != 1 {
		t.Fatal("finished after the deadline fired")
	}
	g.fire()
	if closed.Load() != 1 {
		t.Fatal("closed twice")
	}
	g = newHelloGuard(func() { closed.Add(1) })
	if !g.finish() {
		t.Fatal("finish refused")
	}
	g.fire()
	if closed.Load() != 1 || !g.finish() {
		t.Fatal("a fire after finish closed the session")
	}
	if g.fired() {
		t.Fatal("fired reported after finish")
	}
}
