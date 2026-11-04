package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/seawise-io/seawise-client/tunnelwire/caps"
	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	"github.com/seawise-io/seawise-client/tunnelwire/handshake"
	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/transport"
)

// testEdgeSrv is a protocol-level edge: TLS 1.3 with ALPN sw-tunnel/1,
// yamux, Hello checked and HelloAck signed with the tunnelwire edge code,
// then a signed RouteSet and whatever the test pushes on stream 0.
type testEdgeSrv struct {
	t     *testing.T
	ln    net.Listener
	cert  tls.Certificate
	roots *x509.CertPool
	push  chan *pb.ControlMessage
	got   chan *pb.ControlMessage
	ended chan struct{}
}

func testPKI(t *testing.T) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "session test"}, DNSNames: []string{testName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func newTestEdge(t *testing.T) *testEdgeSrv {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, roots := testPKI(t)
	e := &testEdgeSrv{t: t, ln: ln, cert: cert, roots: roots, push: make(chan *pb.ControlMessage, 8),
		got: make(chan *pb.ControlMessage, 32), ended: make(chan struct{}, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.serve(c)
		}
	}()
	return e
}

func (e *testEdgeSrv) serve(c net.Conn) {
	defer func() { e.ended <- struct{}{} }()
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{e.cert}, NextProtos: []string{wire.ALPN},
		MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return
	}
	cs := tc.ConnectionState()
	ekm, _ := cs.ExportKeyingMaterial(handshake.ExporterLabel, nil, handshake.ExporterLength)
	var exporter [32]byte
	copy(exporter[:], ekm)
	sess, err := yamux.Server(tc, caps.EdgeYamuxConfig(), nil)
	if err != nil {
		return
	}
	defer sess.Close()
	s0, err := sess.AcceptStream()
	if err != nil {
		return
	}
	rd := wire.NewControlReader(s0, nil)
	b, err := rd.Next()
	if err != nil {
		return
	}
	m, err := wire.DecodeControl(b, wire.FromAgent)
	if err != nil || m.GetHello() == nil {
		return
	}
	sid, _ := hex.DecodeString(strings.ReplaceAll(testServer, "-", ""))
	pub := pubOf(seedKey("device"))
	body, code := handshake.CheckHello(m.GetHello(), exporter, pb.Transport_TRANSPORT_TLS, func(kid string) (handshake.Device, bool) {
		return handshake.Device{PublicKey: pub, ServerID: sid, Status: handshake.StatusActive}, kid == protocol.KeyID(pub)
	})
	if code != pb.RefuseCode_REFUSE_UNSPECIFIED {
		e.t.Errorf("hello refused: %s", code)
		return
	}
	d := sha256.Sum256(m.GetHello().GetBody())
	ack, err := handshake.SignHelloAck(seedKey(testEdge), exporter, &pb.HelloAckBody{SessionId: testSessionID, EdgeId: testEdge,
		Capabilities: []string{}, OfferedDigest: d[:], PingIntervalMs: 20000, PingTimeoutMs: 15000,
		MaxStreams: body.GetMaxStreams(), MaxControlBytes: wire.MaxControlMessage, MaxSessionAgeS: 43200})
	if err != nil {
		e.t.Error(err)
		return
	}
	var seq uint64
	send := func(m *pb.ControlMessage) error {
		seq++
		m.Schema, m.Seq = wire.SchemaVersion, seq
		out, err := wire.EncodeControl(m, wire.FromEdge)
		if err != nil {
			return err
		}
		f, _ := wire.AppendControlFrame(nil, out)
		_, err = s0.Write(f)
		return err
	}
	if send(&pb.ControlMessage{Body: &pb.ControlMessage_HelloAck{HelloAck: ack}}) != nil || send(routeSetMsg(e.t, 1, testSessionID)) != nil {
		return
	}
	go func() {
		for m := range e.push {
			if send(m) != nil {
				return
			}
		}
	}()
	for {
		b, err := rd.Next()
		if err != nil {
			return
		}
		m, err := wire.DecodeControl(b, wire.FromAgent)
		if err != nil {
			e.t.Errorf("agent message: %v", err)
			return
		}
		e.got <- m
	}
}

func TestSessionAgainstProtocolEdge(t *testing.T) {
	e := newTestEdge(t)
	ks := testKeySet(t)
	edges, err := transport.NewEdgeList(ks)
	if err != nil {
		t.Fatal(err)
	}
	newDialer := func() (*transport.Dialer, error) {
		return transport.New(transport.Config{Edges: func() *transport.EdgeList { return edges }, Key: seedKey("device"),
			ServerID: testServer, RunID: [16]byte{1}, AgentVersion: "2.0.0", RootCAs: e.roots,
			Getenv: func(string) string { return "" },
			Resolve: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.4.4")}, nil
			},
			DialTCP: func(ctx context.Context, n, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, n, e.ln.Addr().String())
			}})
	}
	routes := make(chan *claims.RouteSet, 4)
	m, err := New(Config{Dial: FromTransport(newDialer), Name: testName, ServerID: testServer, KeyID: deviceKeyID,
		KeySet: func() *protocol.KeySet { return ks }, DataDir: "", Network: make(chan struct{}),
		OnRoutes: func(rs *claims.RouteSet) { routes <- rs }, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	select {
	case rs := <-routes:
		if rs.Edge != testEdge || rs.Version != 1 {
			t.Fatal(rs)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("no session: %+v", m.Status())
	}
	select {
	case got := <-e.got:
		if got.GetRouteSetAck().GetVersion() != 1 {
			t.Fatal(got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no RouteSetAck at the edge")
	}
	if s := m.Status(); !s.Up || s.State != ladder.Own || s.Edge != testEdge || s.Carriage != "tls" {
		t.Fatal(s)
	}
	e.push <- &pb.ControlMessage{Body: &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 1, Flags: flagsDoc(t, 3, "off")}}}
	select {
	case <-e.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("session not closed by the kill switch")
	}
	// The session closes inside the loop step; the status follows it.
	deadline := time.Now().Add(5 * time.Second)
	for s := m.Status(); s.Hold != ladder.HoldFlagsOff || s.Up; s = m.Status() {
		if time.Now().After(deadline) {
			t.Fatal(s)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
