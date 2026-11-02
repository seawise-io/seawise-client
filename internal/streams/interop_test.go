//go:build interop

package streams

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
	"github.com/seawise/client/internal/transport"
	"github.com/seawise/client/internal/visitor"
)

const (
	ioServer  = "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f"
	ioPrivate = "a0000000-0000-4000-8000-00000000000a"
	ioPublic  = "b0000000-0000-4000-8000-00000000000b"
	ioIP      = "8.8.4.4"
)

type ioReq struct {
	App, Token, Stale, Raw string
	Upgrade                bool
	Echo                   string
}

type ioRes struct {
	Reply  string
	Status int
	Header http.Header
	Body   string
	Echo   string
	Err    string
	Reset  bool
}

func ioWait(t *testing.T, dir, name string) []byte {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil && len(b) > 0 {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatal("no", name)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestInteropEdgeDataStreams runs the agent's session manager and data
// stream handler against the platform edge's listener, started by its own
// test harness with INTEROP_DIR, and sends requests through the edge.
func TestInteropEdgeDataStreams(t *testing.T) {
	dir := os.Getenv("INTEROP_DIR")
	if dir == "" {
		t.Skip("INTEROP_DIR not set")
	}
	defer os.WriteFile(filepath.Join(dir, "done"), []byte("1"), 0o600)
	edgeAddr := string(ioWait(t, dir, "addr"))
	ctl := string(ioWait(t, dir, "ctl"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ioWait(t, dir, "ca.pem")) {
		t.Fatal("ca")
	}
	key := func(name string) ed25519.PrivateKey {
		s := sha256.Sum256([]byte("p5b03 test key: " + name))
		return ed25519.NewKeyFromSeed(s[:])
	}
	root := testKey("root")
	entry := func(k ed25519.PrivateKey, role, name string) protocol.KeySetEntry {
		pub := k.Public().(ed25519.PublicKey)
		return protocol.KeySetEntry{KID: protocol.KeyID(pub), Role: role, X: b64.EncodeToString(pub), Status: protocol.StatusActive, Name: name}
	}
	tok, err := protocol.NewKeySet(root, 1, 1_700_000_000, []protocol.KeySetEntry{
		entry(testKey("visitor"), protocol.RoleVisitor, ""), entry(key("edge"), protocol.RoleEdge, edge0)})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan http.Header, 16)
	app := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = rw.Flush()
			_, _ = io.Copy(c, rw)
			return
		}
		b, _ := io.ReadAll(r.Body)
		got <- r.Header.Clone()
		_, _ = w.Write(append([]byte(r.Method+" "+r.RequestURI+" "), b...))
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Serve(ln) }()
	defer app.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	targets := []store.Target{
		{LocalID: "priv", ServerServiceID: ioPrivate, Host: "127.0.0.1", Port: port, Subdomain: "priv"},
		{LocalID: "pub", ServerServiceID: ioPublic, Host: "0.0.0.0", Port: port, Subdomain: "pub", ServerPublic: true},
	}
	fwd := forwarder.New(forwarder.Config{Resolve: func(context.Context, string) ([]netip.Addr, error) { return nil, os.ErrNotExist }})
	defer fwd.Close()
	var apps []forwarder.App
	for _, tg := range targets {
		apps = append(apps, forwarder.App{ID: tg.LocalID, Host: tg.Host, Port: tg.Port, Rule: targetpolicy.RuleFor(tg)})
	}
	fwd.Sync(apps)
	clock := session.NewSignedClock(nil)
	gate, err := visitor.New(visitor.Config{KeySet: func() *protocol.KeySet { return ks }, Now: clock.Now,
		Mode: func() visitor.Mode { return visitor.Enforce }})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Gate: gate, Targets: func() []store.Target { return targets }, Dial: fwd.Dial, ClockReady: clock.Ready})
	if err != nil {
		t.Fatal(err)
	}
	edges, err := transport.NewEdgeList(ks)
	if err != nil {
		t.Fatal(err)
	}
	newDialer := func() (*transport.Dialer, error) {
		return transport.New(transport.Config{Edges: func() *transport.EdgeList { return edges }, Key: key("device"),
			ServerID: ioServer, RunID: [16]byte{9}, AgentVersion: "2.0.0", RootCAs: roots,
			Getenv: func(string) string { return "" },
			Resolve: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(ioIP)}, nil
			},
			DialTCP: func(ctx context.Context, n, a string) (net.Conn, error) {
				var nd net.Dialer
				return nd.DialContext(ctx, n, edgeAddr)
			}})
	}
	m, err := session.New(session.Config{Dial: session.FromTransport(newDialer), Name: "tunnel-us-east.seawise.dev", ServerID: ioServer,
		KeyID: func() string { return protocol.KeyID(key("device").Public().(ed25519.PublicKey)) }, KeySet: func() *protocol.KeySet { return ks },
		Streams: srv.Serve, SignedClock: clock, Network: make(chan struct{}), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(30 * time.Second)
	for !m.Status().Up {
		if time.Now().After(deadline) {
			t.Fatalf("session not up: %+v", m.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}

	rt := func(q ioReq) ioRes {
		t.Helper()
		b, _ := json.Marshal(q)
		res, err := http.Post("http://"+ctl, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out ioRes
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	exp := time.Now().Unix() + 600
	if r := rt(ioReq{App: ioPrivate, Token: token(ioPrivate, exp)}); r.Reply != "TOKEN_REJECTED" {
		t.Fatalf("token accepted before any signed time: %+v", r)
	}
	clock.Observe(time.Now().Unix())
	if r := rt(ioReq{App: ioPrivate, Token: token(ioPrivate, exp)}); r.Status != 200 || r.Body != "POST /echo?x=1 body-bytes" || r.Err != "" {
		t.Fatalf("private with token: %+v", r)
	}
	h := <-got
	for k := range h {
		if strings.Contains(strings.ToLower(k), "seawise") {
			t.Fatalf("SeaWise header reached the app: %v", h)
		}
	}
	if h.Get("X-Request-Id") != "0102" || h.Get("Connection") != "" && !strings.EqualFold(h.Get("Connection"), "close") {
		t.Fatalf("%v", h)
	}
	if r := rt(ioReq{App: ioPrivate}); r.Reply != "TOKEN_REJECTED" {
		t.Fatalf("private without token: %+v", r)
	}
	if r := rt(ioReq{App: ioPrivate, Token: token(ioPublic, exp)}); r.Reply != "TOKEN_REJECTED" {
		t.Fatalf("token for another app: %+v", r)
	}
	if r := rt(ioReq{App: ioPrivate, Token: token(ioPrivate, time.Now().Unix()-3600)}); r.Reply != "TOKEN_REJECTED" {
		t.Fatalf("expired token: %+v", r)
	}
	if r := rt(ioReq{App: ioPublic}); r.Status != 200 || r.Body != "POST /echo?x=1 body-bytes" {
		t.Fatalf("public without token: %+v", r)
	}
	<-got
	ws := "GET /ws HTTP/1.1\r\nHost: b0000000.seawise.dev\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if r := rt(ioReq{App: ioPrivate, Token: token(ioPrivate, exp), Raw: ws, Upgrade: true, Echo: "ping-pong"}); r.Status != 101 || r.Echo != "ping-pong" {
		t.Fatalf("upgrade: %+v", r)
	}
	two := "GET /a HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\nHost: a\r\n\r\n"
	if r := rt(ioReq{App: ioPrivate, Token: token(ioPrivate, exp), Raw: two}); r.Err == "" {
		t.Fatalf("two requests on one stream: %+v", r)
	}
	st := srv.Status()
	if st.Replies["ACCEPTED"] < 4 || st.Replies["TOKEN_REJECTED"] != 4 || st.NoSignedTime != 1 {
		t.Fatalf("%+v", st)
	}
	t.Logf("status %+v", st)
}
