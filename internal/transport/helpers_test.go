package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/seawise-io/seawise-client/tunnelwire/caps"
	"github.com/seawise-io/seawise-client/tunnelwire/handshake"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
	"github.com/seawise-io/seawise-client/tunnelwire/wsconn"

	"github.com/seawise/client/internal/protocol"
)

const (
	testName   = "tunnel-us-east.seawise.dev"
	testEdge   = "edge-us-east-1"
	testServer = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
	// testIP is what the fake resolver answers; DialTCP sends it to the
	// fake edge.
	testIP = "8.8.4.4"
)

func seedKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("transport test key: " + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

type edgeEntry struct {
	name, status string
	key          ed25519.PrivateKey
}

// keySet signs and verifies a key set with the given edge entries plus a
// control key, as the agent would accept it.
func keySet(t testing.TB, entries ...edgeEntry) *protocol.KeySet {
	t.Helper()
	root := seedKey("root")
	keys := []protocol.KeySetEntry{{KID: protocol.KeyID(pubOf(seedKey("control"))), Role: protocol.RoleControl,
		X: protocol.PublicJWK(pubOf(seedKey("control"))).X, Status: protocol.StatusActive}}
	for _, e := range entries {
		keys = append(keys, protocol.KeySetEntry{KID: protocol.KeyID(pubOf(e.key)), Role: protocol.RoleEdge,
			X: protocol.PublicJWK(pubOf(e.key)).X, Status: e.status, Name: e.name})
	}
	tok, err := protocol.NewKeySet(root, 1, time.Now().Unix(), keys)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{pubOf(root)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func edgeList(t testing.TB, entries ...edgeEntry) *EdgeList {
	t.Helper()
	if len(entries) == 0 {
		entries = []edgeEntry{{testEdge, protocol.StatusActive, seedKey("edge")}}
	}
	l, err := NewEdgeList(keySet(t, entries...))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// pki returns a certificate for names and a pool trusting it.
func pki(t testing.TB, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "transport test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, pool
}

// edgeSrv is a fake edge agent listener: raw TLS and the WebSocket
// carriage, Hello checked with the tunnelwire edge checks, HelloAck signed.
type edgeSrv struct {
	t      testing.TB
	ln     net.Listener
	roots  *x509.CertPool
	cert   tls.Certificate
	device ed25519.PrivateKey
	// devicePub, when set, is the registered device key instead.
	devicePub ed25519.PublicKey
	hang      bool
	edge      ed25519.PrivateKey
	edgeID    string
	// answer, when set, replaces the HelloAck (nil: close without answer).
	answer func(exporter [32]byte, h *pb.Hello) *pb.ControlMessage
	// upgradeResponse, when set, replaces the 101.
	upgradeResponse func(key string) string
	alpn            []string
	maxVersion      uint16

	once     sync.Once
	mu       sync.Mutex
	hellos   []*pb.HelloBody
	refuses  []pb.RefuseCode
	upgrades []string
	accepts  int
	sessions []*yamux.Session
	streams  []*yamux.Stream
	wsErrs   []error
}

func newEdge(t testing.TB) *edgeSrv {
	t.Helper()
	cert, roots := pki(t, "*.seawise.dev")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &edgeSrv{t: t, ln: ln, roots: roots, cert: cert, device: seedKey("device"), edge: seedKey("edge"), edgeID: testEdge,
		alpn: []string{wire.ALPN, wire.ALPNWebSocket}, maxVersion: tls.VersionTLS13}
	t.Cleanup(func() {
		_ = ln.Close()
		e.mu.Lock()
		sessions := append([]*yamux.Session(nil), e.sessions...)
		e.mu.Unlock()
		for _, s := range sessions {
			_ = s.Close()
		}
	})
	return e
}

// start serves; fields set before it need no lock.
func (e *edgeSrv) start() { e.once.Do(func() { go e.serve() }) }

func (e *edgeSrv) setAnswer(f func([32]byte, *pb.Hello) *pb.ControlMessage) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.answer = f
}

func (e *edgeSrv) serve() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		e.mu.Lock()
		e.accepts++
		e.mu.Unlock()
		go e.handle(c)
	}
}

func (e *edgeSrv) handle(c net.Conn) {
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{e.cert}, NextProtos: e.alpn,
		MinVersion: tls.VersionTLS12, MaxVersion: e.maxVersion, SessionTicketsDisabled: true})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return
	}
	cs := tc.ConnectionState()
	ekm, _ := cs.ExportKeyingMaterial(handshake.ExporterLabel, nil, handshake.ExporterLength)
	var exporter [32]byte
	copy(exporter[:], ekm)
	var carrier net.Conn = tc
	observed := pb.Transport_TRANSPORT_TLS
	if cs.NegotiatedProtocol == wire.ALPNWebSocket {
		br := bufio.NewReader(tc)
		key, req, ok := readUpgradeRequest(br)
		e.mu.Lock()
		e.upgrades = append(e.upgrades, req)
		e.mu.Unlock()
		if !ok {
			_, _ = tc.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			_ = c.Close()
			return
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			acceptValue(key) + "\r\nSec-WebSocket-Protocol: sw-tunnel.1\r\n\r\n"
		if e.upgradeResponse != nil {
			resp = e.upgradeResponse(key)
		}
		if _, err := tc.Write([]byte(resp)); err != nil || !strings.HasPrefix(resp, "HTTP/1.1 101") {
			_ = c.Close()
			return
		}
		sw := &srvWS{c: tc, br: br, e: e}
		carrier = wsconn.NetConn{Conn: wsconn.New(sw), Under: tc}
		observed = pb.Transport_TRANSPORT_WEBSOCKET
	} else if cs.NegotiatedProtocol != wire.ALPN {
		_ = c.Close()
		return
	}
	cfg := caps.EdgeYamuxConfig()
	sess, err := yamux.Server(carrier, cfg, nil)
	if err != nil {
		_ = c.Close()
		return
	}
	e.mu.Lock()
	e.sessions = append(e.sessions, sess)
	e.mu.Unlock()
	s0, err := sess.AcceptStream()
	if err != nil {
		return
	}
	rd := wire.NewControlReader(s0, nil)
	b, err := rd.Next()
	if err != nil {
		_ = sess.Close()
		return
	}
	m, err := wire.DecodeControl(b, wire.FromAgent)
	if err != nil || m.GetHello() == nil {
		_ = sess.Close()
		return
	}
	h := m.GetHello()
	_ = tc.SetDeadline(time.Time{})
	if e.hang {
		time.Sleep(15 * time.Second)
		_ = sess.Close()
		return
	}
	var reply *pb.ControlMessage
	e.mu.Lock()
	answer := e.answer
	e.mu.Unlock()
	if answer != nil {
		reply = answer(exporter, h)
	} else {
		reply = e.check(exporter, h, observed)
	}
	if reply == nil {
		_ = sess.Close()
		return
	}
	reply.Schema, reply.Seq = wire.SchemaVersion, 1
	out, err := wire.EncodeControl(reply, wire.FromEdge)
	if err != nil {
		e.t.Error(err)
		return
	}
	f, _ := wire.AppendControlFrame(nil, out)
	_, _ = s0.Write(f)
	e.mu.Lock()
	e.streams = append(e.streams, s0)
	e.mu.Unlock()
	if reply.GetHelloRefuse() != nil {
		time.Sleep(50 * time.Millisecond)
		_ = sess.Close()
		return
	}
	go func() { _, _ = io.Copy(s0, s0) }()
}

// check runs the edge's Hello checks and answers HelloAck or HelloRefuse.
func (e *edgeSrv) check(exporter [32]byte, h *pb.Hello, observed pb.Transport) *pb.ControlMessage {
	pub := pubOf(e.device)
	if e.devicePub != nil {
		pub = e.devicePub
	}
	body, code := handshake.CheckHello(h, exporter, observed, func(kid string) (handshake.Device, bool) {
		if kid != protocol.KeyID(pub) {
			return handshake.Device{}, false
		}
		sid, _ := uuidBytes(testServer)
		return handshake.Device{PublicKey: pub, ServerID: sid, Status: handshake.StatusActive}, true
	})
	e.mu.Lock()
	e.refuses = append(e.refuses, code)
	if body != nil {
		e.hellos = append(e.hellos, body)
	}
	e.mu.Unlock()
	if code != pb.RefuseCode_REFUSE_UNSPECIFIED {
		return &pb.ControlMessage{Body: &pb.ControlMessage_HelloRefuse{HelloRefuse: &pb.HelloRefuse{Code: code}}}
	}
	return e.ack(exporter, h.Body, body, nil)
}

func (e *edgeSrv) ack(exporter [32]byte, sent []byte, body *pb.HelloBody, mod func(*pb.HelloAckBody)) *pb.ControlMessage {
	d := sha256.Sum256(sent)
	sid := make([]byte, 16)
	_, _ = rand.Read(sid)
	ab := &pb.HelloAckBody{SessionId: sid, EdgeId: e.edgeID, ProtocolMinor: 0, Capabilities: []string{}, OfferedDigest: d[:],
		PingIntervalMs: 20000, PingTimeoutMs: 15000, MaxStreams: body.GetMaxStreams(), MaxControlBytes: wire.MaxControlMessage,
		MaxSessionAgeS: 43200}
	if mod != nil {
		mod(ab)
	}
	a, err := handshake.SignHelloAck(e.edge, exporter, ab)
	if err != nil {
		e.t.Error(err)
		return nil
	}
	return &pb.ControlMessage{Body: &pb.ControlMessage_HelloAck{HelloAck: a}}
}

func uuidBytes(s string) ([]byte, error) {
	b := make([]byte, 0, 16)
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		var v byte
		for _, c := range []byte{s[i], s[i+1]} {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			}
		}
		b = append(b, v)
		i++
	}
	return b, nil
}

func readUpgradeRequest(br *bufio.Reader) (key, raw string, ok bool) {
	var b strings.Builder
	for {
		l, err := br.ReadString('\n')
		b.WriteString(l)
		if err != nil {
			return "", b.String(), false
		}
		if l == "\r\n" {
			break
		}
		if k, found := strings.CutPrefix(l, "Sec-WebSocket-Key: "); found {
			key = strings.TrimSuffix(k, "\r\n")
		}
	}
	return key, b.String(), key != "" && br.Buffered() == 0
}

// srvWS is the server end of the carriage for tests: masked frames in,
// unmasked out.
type srvWS struct {
	c   net.Conn
	br  *bufio.Reader
	e   *edgeSrv
	wmu sync.Mutex
}

func (s *srvWS) NextReader() (bool, io.Reader, error) {
	var h [2]byte
	if _, err := io.ReadFull(s.br, h[:]); err != nil {
		return false, nil, err
	}
	if h[0] == 0x80|opClose {
		return false, nil, io.EOF
	}
	if h[1]&0x80 == 0 || h[0]&0x0f != opBinary || h[0]&0x80 == 0 {
		err := errors.New("srvWS: unexpected frame")
		s.e.mu.Lock()
		s.e.wsErrs = append(s.e.wsErrs, err)
		s.e.mu.Unlock()
		return false, nil, err
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		_, _ = io.ReadFull(s.br, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		_, _ = io.ReadFull(s.br, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var k [4]byte
	if _, err := io.ReadFull(s.br, k[:]); err != nil {
		return false, nil, err
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(s.br, p); err != nil {
		return false, nil, err
	}
	for i := range p {
		p[i] ^= k[i&3]
	}
	return true, bytes.NewReader(p), nil
}

func (s *srvWS) WriteBinary(p []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return writeServerFrame(s.c, 0x80|opBinary, p)
}

func (s *srvWS) Close() error { return s.c.Close() }

func writeServerFrame(w io.Writer, b0 byte, p []byte) error {
	hdr := []byte{b0}
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 1<<16:
		hdr = append(hdr, 126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	_, err := w.Write(append(hdr, p...))
	return err
}

type dialOpt func(*Config)

// dialer returns a Dialer for the fake edge: the resolver answers testIP
// and DialTCP connects every edge address to the listener.
func (e *edgeSrv) dialer(t testing.TB, opts ...dialOpt) *Dialer {
	t.Helper()
	e.start()
	l := edgeList(t, edgeEntry{testEdge, protocol.StatusActive, e.edge})
	cfg := Config{
		Edges: func() *EdgeList { return l }, Key: e.device, ServerID: testServer, RunID: [16]byte{7},
		AgentVersion: "2.0.0", RootCAs: e.roots, Getenv: func(string) string { return "" },
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(testIP)}, nil
		},
		DialTCP: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == net.JoinHostPort(testIP, edgePort) {
				addr = e.ln.Addr().String()
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func asError(t testing.TB, err error) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %T %v", err, err)
	}
	return e
}
