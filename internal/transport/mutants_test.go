package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

func TestCarriageNames(t *testing.T) {
	if TLS.String() != "tls" || WebSocket.String() != "websocket" {
		t.Fatal(TLS.String(), WebSocket.String())
	}
}

func TestResolveEmptyAnswer(t *testing.T) {
	e := newEdge(t)
	_, err := e.dialer(t, func(c *Config) {
		c.Resolve = func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	}).Dial(ctx(t), testName, TLS)
	if er := asError(t, err); er.Reason != "resolve" || !strings.Contains(err.Error(), "no addresses") {
		t.Fatal(err)
	}
}

func TestEdgeIDLength(t *testing.T) {
	id63 := "edge-" + strings.Repeat("a", 51) + "-b-1234"
	id64 := "edge-" + strings.Repeat("a", 52) + "-b-1234"
	if len(id63) != 63 || len(id64) != 64 {
		t.Fatal(len(id63), len(id64))
	}
	if _, ok := regionOf(id63); !ok {
		t.Fatal("63 refused")
	}
	if _, ok := regionOf(id64); ok {
		t.Fatal("64 accepted")
	}
}

func TestFramesThreeFragments(t *testing.T) {
	third := wire.MaxWebSocketMsg / 3
	frag := func(b0 byte, n int) []byte {
		return append(append([]byte{b0, 0x7f}, binary.BigEndian.AppendUint64(nil, uint64(n))...), make([]byte, n)...)
	}
	in := append(append(frag(0x02, third), frag(0x00, third)...), frag(0x80, wire.MaxWebSocketMsg-2*third+1)...)
	_, err := readAll(newFrames(&scriptConn{r: bytes.NewReader(in)}, nil))
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != 1009 {
		t.Fatal(err)
	}
}

func TestLastKnownBoundaries(t *testing.T) {
	dir := dataDir(t)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: at}}})
	for d, ok := range map[time.Duration]bool{
		LastKnownMaxAge - 1: true, LastKnownMaxAge: false,
		-lastKnownSkew: true, -lastKnownSkew - 1: false, 0: true,
	} {
		now := at.Add(d)
		c := newLastKnown(dir, func() time.Time { return now }, slog.New(slog.DiscardHandler))
		if _, got := c.lookup(testName); got != ok {
			t.Errorf("age %v: %v", d, got)
		}
	}
}

func TestLastKnownRefreshBoundaries(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr(testIP)}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for d, rewrite := range map[time.Duration]bool{lastKnownRefresh - 1: false, lastKnownRefresh: true, 0: false, -1: true} {
		dir := dataDir(t)
		writeLastKnown(t, dir, lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{testName: {Addrs: []string{testIP}, ResolvedAt: at}}})
		now := at.Add(d)
		c := newLastKnown(dir, func() time.Time { return now }, slog.New(slog.DiscardHandler))
		c.remember(testName, addrs)
		if got := c.load().Edges[testName].ResolvedAt.Equal(now); got != (rewrite || d == 0) {
			t.Errorf("age %v: rewritten %v", d, got)
		}
	}
}

func TestProxyPortBounds(t *testing.T) {
	for raw, ok := range map[string]bool{"http://p:1": true, "http://p:65535": true, "http://p:0": false, "http://p:65536": false, "https://p": true, "http://p": true} {
		u, _ := url.Parse(raw)
		p, err := parseProxy(u)
		if (err == nil) != ok {
			t.Error(raw, err)
		}
		if err == nil && (raw == "https://p" && (p.addr != "p:443" || !p.tls) || raw == "http://p" && p.addr != "p:80") {
			t.Error(raw, p.addr)
		}
	}
}

func TestUpgradeMoreRows(t *testing.T) {
	// A header block that starts with CRLF CRLF is a bad status line, read
	// at once.
	_, err := readUpgradeResponse(strings.NewReader("\r\n\r\n"), rfcKey)
	if er := asError(t, err); er.Reason != "upgrade" {
		t.Fatal(err)
	}
	// A control byte in the reason of an otherwise valid 101.
	resp := strings.Replace(good(), "Switching Protocols", "Switching\x01", 1)
	if err := checkUpgradeResponse([]byte(resp), rfcKey); err == nil {
		t.Fatal("control byte in the reason accepted")
	}
	// A tab in the reason and every tchar in a header name are fine.
	resp = strings.Replace(good(), "Switching Protocols", "Switching\tProtocols", 1)
	if err := checkUpgradeResponse([]byte(good("!#$%&'*+-.^_`|~09azAZ: v\r\n")), rfcKey); err != nil {
		t.Fatal(err)
	}
	if err := checkUpgradeResponse([]byte(resp), rfcKey); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultResolver(t *testing.T) {
	d, err := New(Config{Edges: func() *EdgeList { return edgeList(t) }, Key: seedKey("device"), ServerID: testServer,
		RunID: [16]byte{1}, AgentVersion: "2.0.0", DataDir: filepath.Join(os.TempDir(), "x")})
	if err != nil || d.lastKnown == nil {
		t.Fatal(err)
	}
	addrs, err := d.resolve(context.Background(), "localhost")
	if err != nil || len(addrs) == 0 {
		t.Fatal(addrs, err)
	}
}
