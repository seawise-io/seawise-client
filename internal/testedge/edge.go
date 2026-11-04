package testedge

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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

	"github.com/seawise/client/internal/protocol"
)

// App is one app the device API knows for the server.
type App struct {
	ID, LocalID, Name, Host, Subdomain string
	Port                               int
}

// Config describes the edge and the server it serves.
type Config struct {
	Keys     Keys
	CA       *CA
	ServerID string
	// DeviceKey returns the registered device key (nil: none yet).
	DeviceKey func() ed25519.PublicKey
	// TunnelName and APIHost are the names on the certificates.
	TunnelName, APIHost string
	Apps                []App
	// CertAge is how long before the edge's now its certificates were
	// issued (default 30 days).
	CertAge time.Duration
	// DPoPWindow, when set, refuses device calls whose proof iat is
	// further than this from the edge's clock.
	DPoPWindow time.Duration
	// Events, when set, receives every event.
	Events func(Event)
}

// Event is one thing that happened at the edge.
type Event struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Conn     int64     `json:"conn"`
	Carriage string    `json:"carriage,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Edge serves the tunnel and the device API.
type Edge struct {
	cfg    Config
	offset atomic.Int64 // clock offset in ns
	block  atomic.Bool  // raw TLS blocked
	nextID atomic.Int64

	mu       sync.Mutex
	sessions map[int64]*Session
	events   []Event
	calls    map[string]int
}

// Session is one tunnel connection.
type Session struct {
	ID       int64
	Carriage string
	Up       time.Time
	Down     time.Time

	conn  net.Conn
	m     *meter
	mux   *yamux.Session
	hole  atomic.Bool
	wmu   sync.Mutex
	s0    *yamux.Stream
	seq   uint64
	edge  *Edge
	pings atomic.Int64
}

// New checks cfg.
func New(cfg Config) (*Edge, error) {
	if cfg.CA == nil || cfg.DeviceKey == nil || cfg.ServerID == "" || cfg.TunnelName == "" {
		return nil, errors.New("testedge: CA, DeviceKey, ServerID and TunnelName are required")
	}
	if cfg.CertAge == 0 {
		cfg.CertAge = 30 * 24 * time.Hour
	}
	return &Edge{cfg: cfg, sessions: map[int64]*Session{}, calls: map[string]int{}}, nil
}

// Now is the edge's clock.
func (e *Edge) Now() time.Time { return time.Now().Add(time.Duration(e.offset.Load())) }

// SetOffset moves the edge's clock (certificates, signed times, the DPoP
// window) against the real one.
func (e *Edge) SetOffset(d time.Duration) {
	e.offset.Store(int64(d))
	e.event(Event{Kind: "clock", Detail: d.String()})
}

// BlockRawTLS makes the network in front of the edge refuse raw TLS: live
// raw TLS sessions stop carrying anything (no reset) and new raw TLS
// connections are reset after their ClientHello. WebSocket is untouched.
func (e *Edge) BlockRawTLS(on bool) {
	e.block.Store(on)
	if on {
		e.mu.Lock()
		for _, s := range e.sessions {
			if s.Carriage == "tls" && s.Down.IsZero() {
				s.hole.Store(true)
			}
		}
		e.mu.Unlock()
	}
	e.event(Event{Kind: "block_raw", Detail: fmt.Sprint(on)})
}

// Drain asks every live session to reconnect.
func (e *Edge) Drain() {
	for _, s := range e.live() {
		_ = s.send(&pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_ROLLOUT,
			Action: pb.DrainAction_RECONNECT, DeadlineMs: 5000}}})
	}
	e.event(Event{Kind: "drain"})
}

func (e *Edge) live() []*Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []*Session
	for _, s := range e.sessions {
		if s.Down.IsZero() && !s.Up.IsZero() {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b *Session) int { return int(a.ID - b.ID) })
	return out
}

// All returns every session that came up, oldest first.
func (e *Edge) All() []*Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b *Session) int { return int(a.ID - b.ID) })
	return out
}

// Live returns the sessions that are up, oldest first.
func (e *Edge) Live() []*Session { return e.live() }

// Events returns the events so far.
func (e *Edge) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.events)
}

// Calls counts the device calls answered, by method and carrier.
func (e *Edge) Calls() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]int, len(e.calls))
	for k, v := range e.calls {
		out[k] = v
	}
	return out
}

func (e *Edge) event(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	e.mu.Lock()
	e.events = append(e.events, ev)
	f := e.cfg.Events
	e.mu.Unlock()
	if f != nil {
		f(ev)
	}
}

func (e *Edge) countCall(key string) {
	e.mu.Lock()
	e.calls[key]++
	e.mu.Unlock()
}

// Bursts is the activity of the session between from and to.
func (s *Session) Bursts(from, to time.Time, gap time.Duration) []Burst {
	return s.m.bursts(from, to, gap)
}

// Pings is the number of pings the agent sent on the session.
func (s *Session) Pings() int64 { return s.pings.Load() }

// Close ends the session.
func (s *Session) Close() {
	if s.mux != nil {
		_ = s.mux.Close()
	}
	_ = s.conn.Close()
}

// ServeTunnel accepts tunnel connections on ln until it is closed.
func (e *Edge) ServeTunnel(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go e.handle(c)
	}
}

// gate is the connection under TLS: it stops carrying bytes once the
// session is blackholed.
type gate struct {
	net.Conn
	s *Session
}

func (g gate) Read(p []byte) (int, error) {
	for {
		n, err := g.Conn.Read(p)
		// Once blackholed, bytes keep arriving and are dropped; nothing
		// is answered and the connection stays open.
		if err != nil || !g.s.hole.Load() {
			return n, err
		}
	}
}

func (g gate) Write(p []byte) (int, error) {
	if g.s.hole.Load() {
		return len(p), nil
	}
	return g.Conn.Write(p)
}

func (e *Edge) handle(c net.Conn) {
	s := &Session{ID: e.nextID.Add(1), conn: c, edge: e}
	s.m = newMeter(c)
	defer s.m.close()
	defer c.Close()
	e.event(Event{Kind: "accept", Conn: s.ID})
	tc := tls.Server(gate{Conn: c, s: s}, &tls.Config{
		NextProtos: []string{wire.ALPN, wire.ALPNWebSocket}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			if e.block.Load() && slices.Contains(hi.SupportedProtos, wire.ALPN) {
				if tcp, ok := c.(*net.TCPConn); ok {
					_ = tcp.SetLinger(0)
				}
				e.event(Event{Kind: "raw_refused", Conn: s.ID})
				return nil, errors.New("raw TLS blocked")
			}
			return nil, nil
		},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return e.cfg.CA.Leaf(e.cfg.TunnelName, e.Now(), e.cfg.CertAge)
		},
	})
	_ = c.SetDeadline(time.Now().Add(caps.HelloDeadline))
	if err := tc.Handshake(); err != nil {
		e.event(Event{Kind: "tls_failed", Conn: s.ID, Detail: err.Error()})
		return
	}
	cs := tc.ConnectionState()
	ekm, _ := cs.ExportKeyingMaterial(handshake.ExporterLabel, nil, handshake.ExporterLength)
	var exporter [32]byte
	copy(exporter[:], ekm)
	var carrier net.Conn = tc
	observed := pb.Transport_TRANSPORT_TLS
	s.Carriage = "tls"
	if cs.NegotiatedProtocol == wire.ALPNWebSocket {
		br := bufio.NewReader(tc)
		key, ok := readUpgrade(br)
		if !ok {
			_, _ = tc.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return
		}
		if _, err := tc.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			acceptValue(key) + "\r\nSec-WebSocket-Protocol: " + wire.WebSocketProtocol + "\r\n\r\n")); err != nil {
			return
		}
		carrier = wsconn.NetConn{Conn: wsconn.New(&serverWS{c: tc, br: br}), Under: tc}
		observed = pb.Transport_TRANSPORT_WEBSOCKET
		s.Carriage = "websocket"
	} else if cs.NegotiatedProtocol != wire.ALPN {
		return
	}
	mux, err := yamux.Server(carrier, caps.EdgeYamuxConfig(), nil)
	if err != nil {
		return
	}
	s.mux = mux
	defer mux.Close()
	s0, err := mux.AcceptStream()
	if err != nil {
		return
	}
	s.s0 = s0
	rd := wire.NewControlReader(s0, nil)
	b, err := rd.Next()
	if err != nil {
		return
	}
	m, err := wire.DecodeControl(b, wire.FromAgent)
	if err != nil || m.GetHello() == nil {
		e.event(Event{Kind: "bad_hello", Conn: s.ID})
		return
	}
	s.m.mark("hello")
	body, code := handshake.CheckHello(m.GetHello(), exporter, observed, e.registry)
	if code != pb.RefuseCode_REFUSE_UNSPECIFIED {
		e.event(Event{Kind: "hello_refused", Conn: s.ID, Carriage: s.Carriage, Detail: code.String()})
		_ = s.send(&pb.ControlMessage{Body: &pb.ControlMessage_HelloRefuse{HelloRefuse: &pb.HelloRefuse{Code: code}}})
		time.Sleep(50 * time.Millisecond)
		return
	}
	sid := make([]byte, 16)
	_, _ = rand.Read(sid)
	d := sha256.Sum256(m.GetHello().GetBody())
	ack, err := handshake.SignHelloAck(e.cfg.Keys.Edge, exporter, &pb.HelloAckBody{SessionId: sid, EdgeId: e.cfg.Keys.EdgeID,
		Capabilities: []string{}, OfferedDigest: d[:], PingIntervalMs: 20000, PingTimeoutMs: 15000,
		MaxStreams: body.GetMaxStreams(), MaxControlBytes: wire.MaxControlMessage, MaxSessionAgeS: 43200})
	if err != nil {
		return
	}
	if s.send(&pb.ControlMessage{Body: &pb.ControlMessage_HelloAck{HelloAck: ack}}) != nil {
		return
	}
	rs, err := e.routeSet(sid)
	if err != nil || s.send(rs) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	s.Up = time.Now()
	e.mu.Lock()
	e.sessions[s.ID] = s
	e.mu.Unlock()
	e.event(Event{Kind: "up", Conn: s.ID, Carriage: s.Carriage})
	defer func() {
		e.mu.Lock()
		s.Down = time.Now()
		e.mu.Unlock()
		e.event(Event{Kind: "down", Conn: s.ID, Carriage: s.Carriage})
	}()
	for {
		b, err := rd.Next()
		if err != nil {
			return
		}
		m, err := wire.DecodeControl(b, wire.FromAgent)
		if err != nil {
			e.event(Event{Kind: "protocol_error", Conn: s.ID, Detail: err.Error()})
			return
		}
		switch body := m.Body.(type) {
		case *pb.ControlMessage_Ping:
			s.m.mark("ping")
			s.pings.Add(1)
			e.event(Event{Kind: "ping", Conn: s.ID, Carriage: s.Carriage})
			_ = s.send(&pb.ControlMessage{Body: &pb.ControlMessage_Pong{Pong: &pb.Pong{Nonce: body.Ping.GetNonce()}}})
		case *pb.ControlMessage_DeviceCall:
			dc := body.DeviceCall
			s.m.mark("call:" + dc.GetMethod().String())
			status, out := e.answer(dc.GetMethod(), dc.GetBody(), dc.GetDpop())
			e.countCall("stream0:" + dc.GetMethod().String())
			e.event(Event{Kind: "call", Conn: s.ID, Carriage: s.Carriage, Detail: fmt.Sprintf("%s %d", dc.GetMethod(), status)})
			_ = s.send(&pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{
				CallId: dc.GetCallId(), Class: pb.ResultClass_DONE, HttpStatus: uint32(status), Body: out, DpopNonce: newNonce()}}}) //nolint:gosec // G115: an HTTP status
		case *pb.ControlMessage_RouteSetAck:
			s.m.mark("routeset_ack")
		default:
			s.m.mark("other")
		}
	}
}

func (s *Session) send(m *pb.ControlMessage) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.s0 == nil {
		return errors.New("no stream 0")
	}
	s.seq++
	m.Schema, m.Seq = wire.SchemaVersion, s.seq
	out, err := wire.EncodeControl(m, wire.FromEdge)
	if err != nil {
		return err
	}
	f, err := wire.AppendControlFrame(nil, out)
	if err != nil {
		return err
	}
	_, err = s.s0.Write(f)
	return err
}

func (e *Edge) registry(kid string) (handshake.Device, bool) {
	pub := e.cfg.DeviceKey()
	if pub == nil || kid != protocol.KeyID(pub) {
		return handshake.Device{}, false
	}
	sid, err := hex.DecodeString(strings.ReplaceAll(e.cfg.ServerID, "-", ""))
	if err != nil {
		return handshake.Device{}, false
	}
	return handshake.Device{PublicKey: pub, ServerID: sid, Status: handshake.StatusActive}, true
}

func (e *Edge) routeSet(sessionID []byte) (*pb.ControlMessage, error) {
	routes := make([]map[string]any, 0, len(e.cfg.Apps))
	for _, a := range e.cfg.Apps {
		routes = append(routes, map[string]any{"app_id": a.ID, "fqdn": a.Subdomain + ".seawise.dev", "public": false, "access_version": 1})
	}
	tok, err := protocol.NewKeyed(e.cfg.Keys.Edge, protocol.TypRouteSet, map[string]any{"edge": e.cfg.Keys.EdgeID, "server_id": e.cfg.ServerID,
		"session_id": base64.RawURLEncoding.EncodeToString(sessionID), "version": 1, "iat": e.Now().Unix(), "routes": routes})
	if err != nil {
		return nil, err
	}
	return &pb.ControlMessage{Body: &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: tok}}}, nil
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
