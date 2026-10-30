// Package transport dials the edge for seawise-tunnel/1: raw TLS 1.3 or
// the WebSocket carriage, to a tunnel name in the signed edge list,
// through HTTPS_PROXY when set, with the last-known edge address when DNS
// fails, ending in a device-key Hello bound to the carrying TLS
// connection and a verified HelloAck. The session manager drives it.
package transport

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/seawise-io/seawise-client/tunnelwire/caps"
	"github.com/seawise-io/seawise-client/tunnelwire/handshake"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
	"github.com/seawise-io/seawise-client/tunnelwire/wsconn"

	"github.com/seawise/client/internal/netproxy"
	"github.com/seawise/client/internal/protocol"
)

// Carriage is how the yamux byte stream travels to the edge.
type Carriage int

const (
	TLS       Carriage = iota + 1 // raw TLS, ALPN sw-tunnel/1
	WebSocket                     // WebSocket over TLS, ALPN http/1.1
)

// Transport is the HelloBody value for the carriage.
func (c Carriage) Transport() pb.Transport {
	if c == WebSocket {
		return pb.Transport_TRANSPORT_WEBSOCKET
	}
	return pb.Transport_TRANSPORT_TLS
}

func (c Carriage) String() string {
	if c == WebSocket {
		return "websocket"
	}
	return "tls"
}

// Timeouts.
const (
	TCPUserTimeout = 25 * time.Second
	resolveTimeout = 3 * time.Second
	connectTimeout = 5 * time.Second
	proxyTimeout   = 10 * time.Second
	edgePort       = "443"
)

// Config configures a Dialer.
type Config struct {
	// Edges returns the current signed edge list (nil: none verified).
	Edges func() *EdgeList
	// Key is the device key: pure Ed25519 behind crypto.Signer.
	Key          crypto.Signer
	ServerID     string // canonical uuid
	RunID        [16]byte
	AgentVersion string // semver without build metadata
	// Capabilities are offered in Hello; Required must come back.
	Capabilities []string
	Required     []string
	MaxStreams   uint32        // 0: caps.DefaultAgentMaxStreams
	RoutesHeld   func() uint32 // nil: 0
	// KillSwitch reports the persisted local kill switch.
	KillSwitch func() bool
	// DataDir holds the last-known edge addresses ("" keeps none).
	DataDir string
	// Getenv supplies HTTPS_PROXY and NO_PROXY (nil: the environment).
	Getenv netproxy.Getenv
	// RootCAs and ProxyRootCAs verify the edge and an https proxy (nil:
	// system roots).
	RootCAs      *x509.CertPool
	ProxyRootCAs *x509.CertPool
	// Resolve looks a tunnel name up (nil: the system resolver).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// DialTCP opens TCP connections (nil: keepalive off and
	// TCP_USER_TIMEOUT on Linux).
	DialTCP func(ctx context.Context, network, addr string) (net.Conn, error)
	Now     func() time.Time
	Logger  *slog.Logger
}

// Dialer dials sessions.
type Dialer struct {
	cfg       Config
	pub       ed25519.PublicKey
	keyID     string
	serverID  []byte
	getenv    netproxy.Getenv
	resolve   func(ctx context.Context, host string) ([]netip.Addr, error)
	dialTCP   func(ctx context.Context, network, addr string) (net.Conn, error)
	lastKnown *lastKnown
	log       *slog.Logger
}

// New checks the configuration.
func New(cfg Config) (*Dialer, error) {
	d := &Dialer{cfg: cfg}
	if cfg.Edges == nil || cfg.Key == nil {
		return nil, local("config", errors.New("edge list and device key are required"))
	}
	pub, ok := cfg.Key.Public().(ed25519.PublicKey)
	if !ok || protocol.CheckPublicKey(pub) != nil {
		return nil, local("device_key", errors.New("device key is not a valid Ed25519 key"))
	}
	d.pub, d.keyID = pub, protocol.KeyID(pub)
	sid, err := hex.DecodeString(strings.ReplaceAll(cfg.ServerID, "-", ""))
	if err != nil || len(sid) != 16 || len(cfg.ServerID) != 36 || strings.ToLower(cfg.ServerID) != cfg.ServerID {
		return nil, local("config", errors.New("server id is not a canonical uuid"))
	}
	d.serverID = sid
	if cfg.RunID == ([16]byte{}) {
		return nil, local("config", errors.New("run id required"))
	}
	if !wire.ValidAgentVersion(cfg.AgentVersion) {
		return nil, local("agent_version", errors.New("agent version is not a release version"))
	}
	if !wire.ValidCapabilities(cfg.Capabilities) {
		return nil, local("config", errors.New("capabilities must be sorted unique tokens"))
	}
	if d.cfg.MaxStreams == 0 {
		d.cfg.MaxStreams = caps.DefaultAgentMaxStreams
	}
	if _, err := caps.YamuxConfig(d.cfg.MaxStreams); err != nil {
		return nil, local("config", err)
	}
	if d.cfg.Now == nil {
		d.cfg.Now = time.Now
	}
	d.log = cfg.Logger
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	d.getenv = cfg.Getenv
	if d.getenv == nil {
		d.getenv = os.Getenv
	}
	d.resolve = cfg.Resolve
	if d.resolve == nil {
		d.resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	d.dialTCP = cfg.DialTCP
	if d.dialTCP == nil {
		nd := &net.Dialer{KeepAlive: -1, Control: userTimeout}
		d.dialTCP = nd.DialContext
	}
	d.lastKnown = newLastKnown(cfg.DataDir, d.cfg.Now, d.log)
	return d, nil
}

// Session is a verified session: HelloAck checked, stream 0 open, with
// the next seq numbers in both directions. The caller reads RouteSets and
// runs everything after HelloAck.
type Session struct {
	Name      string
	Carriage  Carriage
	Proxied   bool
	LastKnown bool // dialled a stored address because DNS failed
	Mux       *yamux.Session
	Stream0   *yamux.Stream
	Accepted  *handshake.Accepted
	Hello     *pb.HelloBody // as sent; TimeNonce is the signed-time nonce

	conn net.Conn
	rx   *rxConn
	rd   *wire.ControlReader
	wmu  sync.Mutex
	out  wire.SeqOut
	in   wire.SeqIn
}

// Send writes a control message on stream 0 with the next seq.
func (s *Session) Send(m *pb.ControlMessage) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return send(s.Stream0, &s.out, m)
}

// Next reads and strictly decodes the next edge message on stream 0.
func (s *Session) Next() (*pb.ControlMessage, error) {
	b, err := s.rd.Next()
	if err != nil {
		return nil, err
	}
	m, err := wire.DecodeControl(b, wire.FromEdge)
	if m != nil {
		if serr := s.in.Accept(m.GetSeq()); serr != nil {
			return nil, serr
		}
	}
	return m, err
}

// LastReceived is when the last byte arrived on the carrying connection,
// on any stream or frame: protocol liveness.
func (s *Session) LastReceived() time.Time {
	if s.rx == nil {
		return time.Time{}
	}
	return time.Unix(0, s.rx.last.Load())
}

// Close ends the session.
func (s *Session) Close() error {
	err := s.Mux.Close()
	_ = s.conn.Close()
	return err
}

func send(w io.Writer, out *wire.SeqOut, m *pb.ControlMessage) error {
	m.Schema, m.Seq = wire.SchemaVersion, out.Next()
	b, err := wire.EncodeControl(m, wire.FromAgent)
	if err != nil {
		return err
	}
	f, err := wire.AppendControlFrame(nil, b)
	if err != nil {
		return err
	}
	_, err = w.Write(f)
	return err
}

// Dial opens a session to the tunnel name over the carriage.
func (d *Dialer) Dial(ctx context.Context, name string, c Carriage) (*Session, error) {
	if c != TLS && c != WebSocket {
		return nil, local("config", errors.New("unknown carriage"))
	}
	if d.cfg.KillSwitch != nil && d.cfg.KillSwitch() {
		return nil, local("kill_switch", ErrKillSwitch)
	}
	edges := d.cfg.Edges()
	if edges == nil {
		return nil, local("edge_list", ErrNoEdgeList)
	}
	region, ok := edges.Region(name)
	if !ok {
		return nil, local("edge_unlisted", ErrEdgeUnlisted)
	}
	p, err := d.proxyFor(name)
	if err != nil {
		return nil, err
	}
	s := &Session{Name: name, Carriage: c, Proxied: p != nil}
	var raw net.Conn
	var fresh []netip.Addr
	if p != nil {
		pctx, cancel := context.WithTimeout(ctx, proxyTimeout)
		raw, err = d.connect(pctx, p, name)
		cancel()
	} else {
		raw, fresh, err = d.direct(ctx, name)
		s.LastKnown = err == nil && fresh == nil
	}
	if err != nil {
		return nil, d.ctxErr(ctx, err)
	}
	if err := d.handshake(ctx, s, raw, edges, region); err != nil {
		_ = raw.Close()
		return nil, d.ctxErr(ctx, err)
	}
	if fresh != nil && d.lastKnown != nil {
		// Only an edge that proved itself in HelloAck vouches for an address.
		d.lastKnown.remember(name, fresh)
	}
	return s, nil
}

// ctxErr reports a cancelled dial as Local: the caller stopped it, the
// network did not fail.
func (d *Dialer) ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return local("canceled", ctx.Err())
	}
	return err
}

// direct resolves and connects; on a failed lookup it uses the stored
// addresses for the name. It returns the fresh lookup, nil when the stored
// addresses were used, with the connected address first.
func (d *Dialer) direct(ctx context.Context, name string) (net.Conn, []netip.Addr, error) {
	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	addrs, rerr := d.resolve(rctx, name)
	cancel()
	fallback := false
	if rerr != nil || len(addrs) == 0 {
		if d.lastKnown != nil {
			addrs, fallback = d.lastKnown.lookup(name)
		}
		if !fallback {
			if rerr == nil {
				rerr = errors.New("no addresses")
			}
			return nil, nil, blocked(CauseDial, "resolve", fmt.Errorf("resolve %s: %w", name, rerr))
		}
		d.log.Warn("DNS lookup for the tunnel name failed; using its last known address", "name", name)
	}
	var errs []error
	for _, a := range addrs {
		cctx, cancel := context.WithTimeout(ctx, connectTimeout)
		conn, err := d.dialTCP(cctx, "tcp", net.JoinHostPort(a.Unmap().String(), edgePort))
		cancel()
		if err == nil {
			if fallback {
				return conn, nil, nil
			}
			return conn, carriedFirst(a, addrs), nil
		}
		errs = append(errs, opErr(err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, nil, blocked(CauseDial, "connect", errors.Join(errs...))
}

// carriedFirst puts the connected address first, then the rest of the
// same lookup.
func carriedFirst(connected netip.Addr, addrs []netip.Addr) []netip.Addr {
	out := []netip.Addr{connected}
	for _, a := range addrs {
		if a != connected {
			out = append(out, a)
		}
	}
	return out
}

// stage is how far a dial got, for the cause of a failure.
type stage int32

const (
	stageTLS stage = iota
	stageUpgrade
	stageHello
)

func (st stage) cause() string {
	switch st {
	case stageTLS, stageUpgrade:
		return CauseTLS
	}
	return CauseAckSignature
}

// handshake runs TLS, the upgrade, yamux, Hello and HelloAck within the
// Hello deadline from the TCP connection to the edge.
func (d *Dialer) handshake(ctx context.Context, s *Session, raw net.Conn, edges *EdgeList, region string) (err error) {
	deadline := d.cfg.Now().Add(caps.HelloDeadline)
	var st atomic.Int32
	expiry := newHelloGuard(func() { _ = raw.Close() })
	cancelled := newHelloGuard(func() { _ = raw.Close() })
	timer := time.AfterFunc(caps.HelloDeadline, expiry.fire)
	stopCtx := context.AfterFunc(ctx, cancelled.fire)
	defer func() {
		timer.Stop()
		stopCtx()
		if err != nil && expiry.fired() {
			err = blocked(stage(st.Load()).cause(), "hello_deadline", err)
		}
	}()
	_ = raw.SetDeadline(deadline)

	alpn := wire.ALPN
	if s.Carriage == WebSocket {
		alpn = wire.ALPNWebSocket
	}
	tc := tls.Client(raw, &tls.Config{ServerName: s.Name, RootCAs: d.cfg.RootCAs, NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		if noALPN(err) {
			return blocked(CauseALPN, "alpn_refused", err)
		}
		return blocked(CauseTLS, "handshake", err)
	}
	cs := tc.ConnectionState()
	if cs.NegotiatedProtocol != alpn {
		return blocked(CauseALPN, "alpn", fmt.Errorf("edge selected %q", cs.NegotiatedProtocol))
	}
	if cs.Version != tls.VersionTLS13 || cs.DidResume {
		return blocked(CauseTLS, "handshake", errors.New("not a fresh TLS 1.3 session"))
	}
	ekm, err := cs.ExportKeyingMaterial(handshake.ExporterLabel, nil, handshake.ExporterLength)
	if err != nil {
		return blocked(CauseTLS, "exporter", err)
	}
	var exporter [32]byte
	copy(exporter[:], ekm)

	var carrier net.Conn = tc
	if s.Carriage == WebSocket {
		st.Store(int32(stageUpgrade))
		var k [16]byte
		_, _ = rand.Read(k[:])
		key := base64.StdEncoding.EncodeToString(k[:])
		if _, err := tc.Write(upgradeRequest(s.Name, key)); err != nil {
			return blocked(CauseTLS, "upgrade_io", err)
		}
		rest, err := readUpgradeResponse(tc, key)
		if err != nil {
			return err
		}
		carrier = wsconn.NetConn{Conn: wsconn.New(newFrames(tc, rest)), Under: tc}
	}
	st.Store(int32(stageHello))
	if d.cfg.KillSwitch != nil && d.cfg.KillSwitch() {
		return local("kill_switch", ErrKillSwitch)
	}
	rx := &rxConn{Conn: carrier, now: d.cfg.Now}
	rx.last.Store(d.cfg.Now().UnixNano())
	ycfg, _ := caps.YamuxConfig(d.cfg.MaxStreams)
	mux, err := yamux.Client(rx, ycfg, caps.NewAgentGate(caps.AgentBudget, d.cfg.MaxStreams).NewSpan)
	if err != nil {
		return blocked(CauseAckSignature, "yamux", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = mux.Close()
		}
	}()
	s0, err := mux.OpenStream(ctx)
	if err != nil {
		return blocked(CauseAckSignature, "stream0", err)
	}
	_ = s0.SetDeadline(deadline)
	body, sent, err := d.hello(exporter, s.Carriage)
	if err != nil {
		return err
	}
	if err := send(s0, &s.out, &pb.ControlMessage{Body: &pb.ControlMessage_Hello{Hello: sent}}); err != nil {
		return blocked(CauseAckSignature, "hello_io", err)
	}
	rd := wire.NewControlReader(s0, nil)
	b, err := rd.Next()
	if err != nil {
		return blocked(CauseAckSignature, "ack_io", err)
	}
	m, err := wire.DecodeControl(b, wire.FromEdge)
	if err != nil || s.in.Accept(m.GetSeq()) != nil {
		return blocked(CauseAckSignature, "ack_malformed", errors.New("malformed first edge message"))
	}
	if r := m.GetHelloRefuse(); r != nil {
		return refusal(r)
	}
	ack := m.GetHelloAck()
	if ack == nil {
		return blocked(CauseAckSignature, "ack_missing", errors.New("first edge message is not HelloAck"))
	}
	acc, err := verifyAck(ack, exporter, handshake.Sent{Body: sent.Body, Hello: body, Required: d.cfg.Required}, edges, region)
	if err != nil {
		return err
	}
	// Disarm both closers first; one that already fired has closed the
	// connection, so the session is never handed over closed.
	if !expiry.finish() {
		return blocked(CauseAckSignature, "hello_deadline", errors.New("hello deadline passed"))
	}
	if !cancelled.finish() {
		return local("canceled", ctx.Err())
	}
	_ = s0.SetDeadline(time.Time{})
	_ = tc.SetReadDeadline(time.Time{})
	s.Mux, s.Stream0, s.Accepted, s.Hello, s.conn, s.rd, s.rx = mux, s0, acc, body, tc, rd, rx
	ok = true
	return nil
}

// rxConn records when bytes arrive under yamux.
type rxConn struct {
	net.Conn
	now  func() time.Time
	last atomic.Int64
}

func (c *rxConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(c.now().UnixNano())
	}
	return n, err
}

// noALPN reports the no_application_protocol alert (120). crypto/tls
// surfaces a received alert only as an *net.OpError "remote error" whose
// cause has an unexported type.
func noALPN(err error) bool {
	var ae tls.AlertError
	if errors.As(err, &ae) {
		return ae == 120
	}
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "remote error" && oe.Err != nil && oe.Err.Error() == "tls: no application protocol"
}

// hello builds and signs the Hello for this connection.
func (d *Dialer) hello(exporter [32]byte, c Carriage) (*pb.HelloBody, *pb.Hello, error) {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	var routes uint32
	if d.cfg.RoutesHeld != nil {
		routes = min(d.cfg.RoutesHeld(), wire.MaxRoutesHeld)
	}
	body := &pb.HelloBody{ServerId: d.serverID, KeyId: d.keyID, RunId: d.cfg.RunID[:],
		Capabilities: slices.Clone(d.cfg.Capabilities), AgentVersion: d.cfg.AgentVersion,
		Transport: c.Transport(), TimeNonce: nonce, RoutesHeld: routes, MaxStreams: d.cfg.MaxStreams}
	h, err := signHello(d.cfg.Key, d.pub, exporter, body)
	return body, h, err
}

// signHello signs the encoded body over the exporter through the device
// key's crypto.Signer (pure Ed25519).
func signHello(key crypto.Signer, pub ed25519.PublicKey, exporter [32]byte, body *pb.HelloBody) (*pb.Hello, error) {
	b, err := wire.EncodeHelloBody(body)
	if err != nil {
		return nil, local("hello", err)
	}
	msg := handshake.HelloMessage(exporter, b)
	sig, err := key.Sign(nil, msg, crypto.Hash(0))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return nil, local("device_key", errors.New("device key did not sign"))
	}
	return &pb.Hello{Body: b, Signature: sig}, nil
}

// verifyAck checks HelloAck against every listed key of its edge id, and
// that the edge serves the dialled region.
func verifyAck(ack *pb.HelloAck, exporter [32]byte, sent handshake.Sent, edges *EdgeList, region string) (*handshake.Accepted, error) {
	body, derr := wire.DecodeHelloAckBody(ack.GetBody())
	var keys []ed25519.PublicKey
	if derr == nil {
		keys = edges.Keys(body.EdgeId)
	}
	if len(keys) == 0 {
		keys = []ed25519.PublicKey{nil}
	}
	var err error
	for _, k := range keys {
		var acc *handshake.Accepted
		acc, err = handshake.VerifyHelloAck(ack, exporter, sent, func(string) (ed25519.PublicKey, bool) { return k, k != nil })
		if err == nil {
			if r, _ := regionOf(acc.Ack.EdgeId); r != region {
				return nil, blocked(CauseAckSignature, "edge_region", errors.New("edge serves another region"))
			}
			return acc, nil
		}
		if handshake.CodeOf(err) == handshake.CodeEdgeTooOld {
			return nil, &Error{Kind: Refused, Cause: CauseEdgeTooOld, Reason: "edge_too_old", Err: err}
		}
	}
	return nil, blocked(CauseAckSignature, string(handshake.CodeOf(err)), err)
}

// helloGuard runs close at most once, unless finish came first.
type helloGuard struct {
	mu    sync.Mutex
	close func()
	done  bool // finished or fired
	hit   bool // fired
}

func newHelloGuard(close func()) *helloGuard { return &helloGuard{close: close} }

func (g *helloGuard) fire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done {
		return
	}
	g.done, g.hit = true, true
	g.close()
}

// finish disarms the guard; false when it already fired.
func (g *helloGuard) finish() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.done = true
	return !g.hit
}

func (g *helloGuard) fired() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hit
}

// closeOnDone closes conn when ctx ends; the returned func stops that.
func closeOnDone(ctx context.Context, conn net.Conn) func() bool {
	return context.AfterFunc(ctx, func() { _ = conn.Close() })
}
