//go:build interop

package devapi

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/transport"
)

const ioServer = "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f"

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

func ioKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("p5b03 test key: " + name))
	return ed25519.NewKeyFromSeed(s[:])
}

// TestInteropEdgeDeviceCalls runs the agent's session manager and device
// API client against the platform edge's listener and relay client,
// started by its own harness with INTEROP_DIR, in front of a device-api
// stand-in reachable through the relay and as the HTTPS twin.
func TestInteropEdgeDeviceCalls(t *testing.T) {
	dir := os.Getenv("INTEROP_DIR")
	if dir == "" {
		t.Skip("INTEROP_DIR not set")
	}
	defer os.WriteFile(filepath.Join(dir, "done"), []byte("1"), 0o600)
	edgeAddr := string(ioWait(t, dir, "addr"))
	ctl := string(ioWait(t, dir, "ctl"))
	apiURL := string(ioWait(t, dir, "api"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ioWait(t, dir, "ca.pem")) {
		t.Fatal("ca")
	}
	apiRoots := x509.NewCertPool()
	if !apiRoots.AppendCertsFromPEM(ioWait(t, dir, "api.pem")) {
		t.Fatal("api ca")
	}
	root := ioKey("root")
	edgePub := ioKey("edge").Public().(ed25519.PublicKey)
	tok, err := protocol.NewKeySet(root, 1, 1_700_000_000, []protocol.KeySetEntry{{KID: protocol.KeyID(edgePub), Role: protocol.RoleEdge,
		X: base64.RawURLEncoding.EncodeToString(edgePub), Status: protocol.StatusActive, Name: "edge-us-east-0"}})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	edges, err := transport.NewEdgeList(ks)
	if err != nil {
		t.Fatal(err)
	}
	newDialer := func() (*transport.Dialer, error) {
		return transport.New(transport.Config{Edges: func() *transport.EdgeList { return edges }, Key: ioKey("device"),
			ServerID: ioServer, RunID: [16]byte{9}, AgentVersion: "2.0.0", RootCAs: roots,
			Getenv: func(string) string { return "" },
			Resolve: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.4.4")}, nil
			},
			DialTCP: func(ctx context.Context, n, a string) (net.Conn, error) {
				var nd net.Dialer
				return nd.DialContext(ctx, n, edgeAddr)
			}})
	}
	m, err := session.New(session.Config{Dial: session.FromTransport(newDialer), Name: "tunnel-us-east.seawise.dev", ServerID: ioServer,
		KeyID: func() string { return protocol.KeyID(ioKey("device").Public().(ed25519.PublicKey)) }, KeySet: func() *protocol.KeySet { return ks },
		Network: make(chan struct{}), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = m.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitUp := func() {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for !m.Status().Up {
			if time.Now().After(deadline) {
				t.Fatalf("session not up: %+v", m.Status())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitUp()

	caller, err := devicecall.New(devicecall.Config{Version: "2.0.0", Client: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: apiRoots}}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Caller: caller, Origin: func() string { return apiURL }, Key: func() crypto.Signer { return ioKey("device") }, Stream0: m})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) string {
		t.Helper()
		res, err := http.Get("http://" + ctl + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	do := func(call Call) Answer {
		t.Helper()
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		a, err := c.Do(cctx, call)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// The first call meets the nonce challenge on stream 0 and is retried
	// there with the device-api nonce.
	if a := do(Call{Method: pb.DeviceMethod_LIST_APPS}); !a.Relayed || a.Status != 200 {
		t.Fatalf("list: %+v %s", a, a.Body)
	}
	k1, k2 := "11111111111111111111111111111111", "22222222222222222222222222222222"
	body := []byte(`{"apps":[{"local_id":"a"}]}`)
	a1 := do(Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: k1, Body: body})
	a2 := do(Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: k1, Body: body})
	if !a1.Relayed || !a2.Relayed || a1.Status != 200 || string(a1.Body) != string(a2.Body) || get("/runs?key="+k1) != "1" {
		t.Fatalf("dedupe over stream 0: %+v %+v runs %s", a1, a2, get("/runs?key="+k1))
	}
	if a := do(Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: k1, Body: []byte(`{"apps":[]}`)}); a.Status != 409 || !strings.Contains(string(a.Body), "idempotency_mismatch") {
		t.Fatalf("mismatch: %+v %s", a, a.Body)
	}

	// The edge session closes after device-api ran the call: the HTTPS
	// resend under the same key gets the stored answer.
	get("/drop?key=" + k2)
	a3 := do(Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: k2, Body: body})
	if a3.Relayed || a3.Status != 200 || get("/runs?key="+k2) != "1" {
		t.Fatalf("drop mid-call: %+v %s runs %s", a3, a3.Body, get("/runs?key="+k2))
	}
	waitUp()
	a4 := do(Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: k2, Body: body})
	if !a4.Relayed || string(a4.Body) != string(a3.Body) || get("/runs?key="+k2) != "1" {
		t.Fatalf("after reconnect: %+v %s runs %s", a4, a4.Body, get("/runs?key="+k2))
	}
	if a := do(Call{Method: pb.DeviceMethod_REPORT_HEALTH, Body: []byte(`{"apps":[]}`)}); !a.Relayed || a.Status != 200 {
		t.Fatalf("health: %+v", a)
	}
	t.Logf("device-api saw:\n%s", get("/seen"))
}
