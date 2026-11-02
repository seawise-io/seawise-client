//go:build interop

package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

// TestInteropEdge dials the platform edge's agent listener, started by its
// own test harness with INTEROP_DIR, on both carriages, directly and
// through a CONNECT proxy.
func TestInteropEdge(t *testing.T) {
	dir := os.Getenv("INTEROP_DIR")
	if dir == "" {
		t.Skip("INTEROP_DIR not set")
	}
	addr, err := os.ReadFile(filepath.Join(dir, "addr"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca")
	}
	key := func(name string) ed25519.PrivateKey {
		s := sha256.Sum256([]byte("p5b03 test key: " + name))
		return ed25519.NewKeyFromSeed(s[:])
	}
	l := edgeList(t, edgeEntry{"edge-us-east-0", protocol.StatusActive, key("edge")})
	edgeAddr := string(addr)
	proxy := &fakeProxy{edge: edgeAddr}
	proxy.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.ln.Close()
	go proxy.serve()
	for _, viaProxy := range []bool{false, true} {
		for _, c := range []Carriage{TLS, WebSocket} {
			name := c.String()
			if viaProxy {
				name += " proxy"
			}
			t.Run(name, func(t *testing.T) {
				vars := map[string]string{}
				if viaProxy {
					vars["HTTPS_PROXY"] = "http://agent:pw@" + proxy.ln.Addr().String()
				}
				d, err := New(Config{Edges: func() *EdgeList { return l }, Key: key("device"),
					ServerID: "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f", RunID: [16]byte{9}, AgentVersion: "2.0.0", RootCAs: roots,
					Getenv: func(k string) string { return vars[k] },
					Resolve: func(context.Context, string) ([]netip.Addr, error) {
						return []netip.Addr{netip.MustParseAddr(testIP)}, nil
					},
					DialTCP: func(ctx context.Context, n, a string) (net.Conn, error) {
						if a == net.JoinHostPort(testIP, edgePort) {
							a = edgeAddr
						}
						var nd net.Dialer
						return nd.DialContext(ctx, n, a)
					}})
				if err != nil {
					t.Fatal(err)
				}
				s, err := d.Dial(ctx(t), "tunnel-us-east.seawise.dev", c)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				if s.Accepted.Ack.EdgeId != "edge-us-east-0" || s.Proxied != viaProxy {
					t.Fatal(s.Accepted.Ack, s.Proxied)
				}
				_ = s.Stream0.SetReadDeadline(time.Now().Add(5 * time.Second))
				m, err := s.Next()
				if err != nil || m.GetRouteSet() == nil {
					t.Fatalf("want RouteSet, got %v %v", m, err)
				}
				if c == WebSocket && !viaProxy && !testing.Short() {
					time.Sleep(11 * time.Second)
				}
				if err := s.Send(&pb.ControlMessage{Body: &pb.ControlMessage_Ping{Ping: &pb.Ping{Nonce: 42}}}); err != nil {
					t.Fatal(err)
				}
				for {
					_ = s.Stream0.SetReadDeadline(time.Now().Add(5 * time.Second))
					m, err := s.Next()
					if err != nil {
						t.Fatal(err)
					}
					if p := m.GetPong(); p != nil {
						if p.Nonce != 42 {
							t.Fatal(p)
						}
						break
					}
				}
			})
		}
	}
}
