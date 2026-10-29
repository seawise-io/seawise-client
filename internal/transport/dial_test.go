package transport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/handshake"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"google.golang.org/protobuf/proto"

	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/protocol"
)

func ctx(t testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// echo checks that stream 0 carries bytes both ways after HelloAck (the
// fake edge echoes it).
func echo(t *testing.T, s *Session, msg string) {
	t.Helper()
	_ = s.Stream0.SetDeadline(time.Now().Add(5 * time.Second))
	defer s.Stream0.SetDeadline(time.Time{})
	if _, err := s.Stream0.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s.Stream0, got); err != nil || string(got) != msg {
		t.Fatal(string(got), err)
	}
}

func TestDialBothCarriages(t *testing.T) {
	for _, c := range []Carriage{TLS, WebSocket} {
		t.Run(c.String(), func(t *testing.T) {
			e := newEdge(t)
			s, err := e.dialer(t).Dial(ctx(t), testName, c)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if s.Carriage != c || s.Proxied || s.LastKnown || s.Name != testName {
				t.Fatalf("%+v", s)
			}
			if s.Accepted.Ack.EdgeId != testEdge || s.Hello.Transport != c.Transport() || len(s.Hello.TimeNonce) != 16 {
				t.Fatal(s.Accepted.Ack, s.Hello)
			}
			e.mu.Lock()
			hellos := e.hellos
			e.mu.Unlock()
			if len(hellos) != 1 || hellos[0].Transport != c.Transport() || hellos[0].AgentVersion != "2.0.0" ||
				hellos[0].MaxStreams != 128 || hellos[0].KeyId != protocol.KeyID(pubOf(e.device)) {
				t.Fatal(hellos)
			}
			echo(t, s, "after hello")
		})
	}
}

func TestDialUpgradeRequestExact(t *testing.T) {
	e := newEdge(t)
	s, err := e.dialer(t).Dial(ctx(t), testName, WebSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e.mu.Lock()
	req := e.upgrades[0]
	e.mu.Unlock()
	key, _, _ := strings.Cut(strings.SplitAfter(req, "Sec-WebSocket-Key: ")[1], "\r\n")
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		t.Fatal(key)
	}
	if req != string(upgradeRequest(testName, key)) {
		t.Fatalf("%q", req)
	}
}

// go-yamux sets a write deadline before its writes; over the WebSocket
// carriage that deadline must reach the TLS connection, and the session
// must outlive go-yamux's 10 s write timeout while idle.
func TestWebSocketSessionSurvivesIdle(t *testing.T) {
	if testing.Short() || os.Getenv("SEAWISE_SKIP_SLOW_TESTS") != "" {
		t.Skip("waits 11 s")
	}
	e := newEdge(t)
	s, err := e.dialer(t).Dial(ctx(t), testName, WebSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	echo(t, s, "before")
	time.Sleep(11 * time.Second)
	if s.Mux.IsClosed() {
		t.Fatal("session closed while idle")
	}
	echo(t, s, "after idle")
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.wsErrs) != 0 {
		t.Fatal(e.wsErrs)
	}
}

func TestDialSessionSendNext(t *testing.T) {
	e := newEdge(t)
	s, err := e.dialer(t).Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The fake edge echoes stream 0, so the agent's own Ping comes back:
	// seq 2 continues after Hello, and an agent message is refused by the
	// edge-direction decoder.
	if err := s.Send(&pb.ControlMessage{Body: &pb.ControlMessage_Ping{Ping: &pb.Ping{Nonce: 1}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Next(); wire.CodeOf(err) != wire.CodeDirection {
		t.Fatal(err)
	}
}

func TestDialWithIdentityKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ks, err := identity.Open("file", dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	e := newEdge(t)
	e.devicePub = key.PublicKey()
	s, err := e.dialer(t, func(c *Config) { c.Key = key }).Dial(ctx(t), testName, WebSocket)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestHelloVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tunnelwire", "testdata", "vectors", "hello.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys  []struct{ Name, Seed string } `json:"keys"`
		Cases []struct {
			Name, Kind, Input, Expect string
			Context                   struct{ Exporter string } `json:"context"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PrivateKey{}
	for _, k := range v.Keys {
		seed, _ := hex.DecodeString(k.Seed)
		priv := ed25519.NewKeyFromSeed(seed)
		keys[protocol.KeyID(pubOf(priv))] = priv
	}
	n := 0
	for _, c := range v.Cases {
		if c.Kind != "hello" || c.Expect != "ok" {
			continue
		}
		in, _ := base64.StdEncoding.DecodeString(c.Input)
		var h pb.Hello
		if err := proto.Unmarshal(in, &h); err != nil {
			t.Fatal(c.Name, err)
		}
		body, err := wire.DecodeHelloBody(h.Body)
		if err != nil {
			t.Fatal(c.Name, err)
		}
		priv := keys[body.KeyId]
		var ex [32]byte
		b, _ := hex.DecodeString(c.Context.Exporter)
		copy(ex[:], b)
		got, err := signHello(priv, pubOf(priv), ex, body)
		if err != nil || !bytes.Equal(got.Body, h.Body) || !bytes.Equal(got.Signature, h.Signature) {
			t.Errorf("%s: %v", c.Name, err)
		}
		n++
	}
	if n < 4 {
		t.Fatal("too few vectors", n)
	}
}

func TestSignHelloRefusesBadSigner(t *testing.T) {
	body := &pb.HelloBody{ServerId: make([]byte, 16), KeyId: protocol.KeyID(pubOf(seedKey("a"))), RunId: make([]byte, 16),
		AgentVersion: "2.0.0", Transport: pb.Transport_TRANSPORT_TLS, TimeNonce: make([]byte, 16), MaxStreams: 128}
	// A signer whose public key does not match: refused locally.
	if _, err := signHello(seedKey("a"), pubOf(seedKey("b")), [32]byte{}, body); KindOf(err) != Local {
		t.Fatal(err)
	}
	body.AgentVersion = "dev"
	if _, err := signHello(seedKey("a"), pubOf(seedKey("a")), [32]byte{}, body); KindOf(err) != Local {
		t.Fatal(err)
	}
}

func TestNewValidates(t *testing.T) {
	e := newEdge(t)
	ok := func(c *Config) {}
	for name, mod := range map[string]func(*Config){
		"no key":         func(c *Config) { c.Key = nil },
		"no edges":       func(c *Config) { c.Edges = nil },
		"not ed25519":    func(c *Config) { c.Key = badSigner{} },
		"server upper":   func(c *Config) { c.ServerID = strings.ToUpper(testServer) },
		"server short":   func(c *Config) { c.ServerID = testServer[:35] },
		"server no dash": func(c *Config) { c.ServerID = strings.ReplaceAll(testServer, "-", "") + "0000" },
		"run id":         func(c *Config) { c.RunID = [16]byte{} },
		"version":        func(c *Config) { c.AgentVersion = "dev" },
		"caps":           func(c *Config) { c.Capabilities = []string{"b", "a"} },
		"streams":        func(c *Config) { c.MaxStreams = 5000 },
	} {
		cfg := baseConfig(e)
		mod(&cfg)
		if _, err := New(cfg); KindOf(err) != Local {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := baseConfig(e)
	ok(&cfg)
	d, err := New(cfg)
	if err != nil || d.cfg.MaxStreams != 128 {
		t.Fatal(err)
	}
}

type badSigner struct{}

func (badSigner) Public() crypto.PublicKey                                  { return "x" }
func (badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

func baseConfig(e *edgeSrv) Config {
	l := edgeList(e.t, edgeEntry{testEdge, protocol.StatusActive, e.edge})
	return Config{Edges: func() *EdgeList { return l }, Key: e.device, ServerID: testServer, RunID: [16]byte{1}, AgentVersion: "2.0.0"}
}

func TestDialLocalGates(t *testing.T) {
	e := newEdge(t)
	on := true
	d := e.dialer(t, func(c *Config) { c.KillSwitch = func() bool { return on } })
	if _, err := d.Dial(ctx(t), testName, TLS); !errors.Is(err, ErrKillSwitch) || KindOf(err) != Local {
		t.Fatal(err)
	}
	on = false
	for _, name := range []string{"tunnel-eu-west.seawise.dev", "evil.example", "tunnel-us-east.seawise.dev.evil.example"} {
		if _, err := d.Dial(ctx(t), name, TLS); !errors.Is(err, ErrEdgeUnlisted) || KindOf(err) != Local {
			t.Fatal(name, err)
		}
	}
	if _, err := d.Dial(ctx(t), testName, Carriage(9)); KindOf(err) != Local {
		t.Fatal(err)
	}
	d2 := e.dialer(t, func(c *Config) { c.Edges = func() *EdgeList { return nil } })
	if _, err := d2.Dial(ctx(t), testName, TLS); !errors.Is(err, ErrNoEdgeList) {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.accepts != 0 {
		t.Fatal("a local refusal opened a connection")
	}
}

func TestDialKillSwitchBeforeHello(t *testing.T) {
	e := newEdge(t)
	calls := 0
	d := e.dialer(t, func(c *Config) { c.KillSwitch = func() bool { calls++; return calls > 1 } })
	_, err := d.Dial(ctx(t), testName, TLS)
	if !errors.Is(err, ErrKillSwitch) {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.hellos) != 0 {
		t.Fatal("Hello sent with the kill switch on")
	}
}

func TestDialCancelledIsLocal(t *testing.T) {
	e := newEdge(t)
	e.hang = true
	c, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	if _, err := e.dialer(t).Dial(c, testName, TLS); KindOf(err) != Local || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestExporterBinding(t *testing.T) {
	e := newEdge(t)
	var captured *pb.Hello
	e.answer = func(ex [32]byte, h *pb.Hello) *pb.ControlMessage {
		captured = h
		return e.check(ex, h, pb.Transport_TRANSPORT_TLS)
	}
	s, err := e.dialer(t).Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// The captured Hello on another connection: the edge's check refuses.
	var code pb.RefuseCode
	e.setAnswer(func(ex [32]byte, h *pb.Hello) *pb.ControlMessage {
		_, code = handshake.CheckHello(captured, ex, pb.Transport_TRANSPORT_TLS, func(string) (handshake.Device, bool) {
			sid, _ := uuidBytes(testServer)
			return handshake.Device{PublicKey: pubOf(e.device), ServerID: sid, Status: handshake.StatusActive}, true
		})
		return e.check(ex, h, pb.Transport_TRANSPORT_TLS)
	})
	s, err = e.dialer(t).Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if code != pb.RefuseCode_INVALID_PROOF {
		t.Fatal(code)
	}
}

func TestDialTransportMismatchRefused(t *testing.T) {
	// The agent's transport must match the carriage the edge observed.
	e := newEdge(t)
	e.answer = func(ex [32]byte, h *pb.Hello) *pb.ControlMessage {
		return e.check(ex, h, pb.Transport_TRANSPORT_TLS)
	}
	_, err := e.dialer(t).Dial(ctx(t), testName, WebSocket)
	if er := asError(t, err); er.Code != pb.RefuseCode_BAD_REQUEST || er.Kind != Transient {
		t.Fatal(err)
	}
}

func TestDialRefusals(t *testing.T) {
	for code, kind := range map[pb.RefuseCode]Kind{
		pb.RefuseCode_INVALID_PROOF: Auth, pb.RefuseCode_KEY_REVOKED: Auth, pb.RefuseCode_PROTOCOL_DISABLED: Refused,
		pb.RefuseCode_VERSION_TOO_OLD: Refused, pb.RefuseCode_OVERLOADED: Transient, pb.RefuseCode_EDGE_NOT_READY: Transient,
	} {
		e := newEdge(t)
		e.answer = func([32]byte, *pb.Hello) *pb.ControlMessage {
			return &pb.ControlMessage{Body: &pb.ControlMessage_HelloRefuse{HelloRefuse: &pb.HelloRefuse{Code: code, RetryAfterMs: 1500}}}
		}
		_, err := e.dialer(t).Dial(ctx(t), testName, WebSocket)
		er := asError(t, err)
		if er.Kind != kind || er.Code != code || er.RetryAfter != 1500*time.Millisecond {
			t.Errorf("%v: %v", code, err)
		}
	}
}

func TestDialAckChecks(t *testing.T) {
	rogue := seedKey("rogue")
	cases := []struct {
		name  string
		setup func(e *edgeSrv) []dialOpt
		kind  Kind
		cause string
	}{
		{"unlisted edge id", func(e *edgeSrv) []dialOpt { e.edgeID = "edge-us-east-9"; return nil }, Blocked, CauseAckSignature},
		{"edge of another region", func(e *edgeSrv) []dialOpt {
			eu := seedKey("eu")
			l := edgeList(t, edgeEntry{testEdge, protocol.StatusActive, e.edge}, edgeEntry{"edge-eu-west-1", protocol.StatusActive, eu})
			e.edgeID, e.edge = "edge-eu-west-1", eu
			return []dialOpt{func(c *Config) { c.Edges = func() *EdgeList { return l } }}
		}, Blocked, CauseAckSignature},
		{"signed by another key", func(e *edgeSrv) []dialOpt {
			l := edgeList(t, edgeEntry{testEdge, protocol.StatusActive, e.edge})
			e.edge = rogue
			return []dialOpt{func(c *Config) { c.Edges = func() *EdgeList { return l } }}
		}, Blocked, CauseAckSignature},
		{"digest mismatch", func(e *edgeSrv) []dialOpt {
			e.answer = func(ex [32]byte, h *pb.Hello) *pb.ControlMessage {
				body, _ := wire.DecodeHelloBody(h.Body)
				return e.ack(ex, append([]byte{0}, h.Body...), body, nil)
			}
			return nil
		}, Blocked, CauseAckSignature},
		{"more streams than offered", func(e *edgeSrv) []dialOpt {
			e.answer = func(ex [32]byte, h *pb.Hello) *pb.ControlMessage {
				body, _ := wire.DecodeHelloBody(h.Body)
				return e.ack(ex, h.Body, body, func(a *pb.HelloAckBody) { a.MaxStreams = 129 })
			}
			return nil
		}, Blocked, CauseAckSignature},
		{"no answer", func(e *edgeSrv) []dialOpt {
			e.answer = func([32]byte, *pb.Hello) *pb.ControlMessage { return nil }
			return nil
		}, Blocked, CauseAckSignature},
		{"not a HelloAck", func(e *edgeSrv) []dialOpt {
			e.answer = func([32]byte, *pb.Hello) *pb.ControlMessage {
				return &pb.ControlMessage{Body: &pb.ControlMessage_Pong{Pong: &pb.Pong{Nonce: 1}}}
			}
			return nil
		}, Blocked, CauseAckSignature},
		{"required capability missing", func(e *edgeSrv) []dialOpt {
			return []dialOpt{func(c *Config) { c.Capabilities, c.Required = []string{"x"}, []string{"x"} }}
		}, Refused, CauseEdgeTooOld},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEdge(t)
			opts := c.setup(e)
			_, err := e.dialer(t, opts...).Dial(ctx(t), testName, TLS)
			er := asError(t, err)
			if er.Kind != c.kind || er.Cause != c.cause {
				t.Fatal(err)
			}
		})
	}
}

func TestDialAcceptsNextEdgeKey(t *testing.T) {
	e := newEdge(t)
	next := seedKey("next")
	l := edgeList(t, edgeEntry{testEdge, protocol.StatusActive, e.edge}, edgeEntry{testEdge, protocol.StatusNext, next})
	e.edge = next
	s, err := e.dialer(t, func(c *Config) { c.Edges = func() *EdgeList { return l } }).Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
}

func TestDialHelloDeadline(t *testing.T) {
	if testing.Short() || os.Getenv("SEAWISE_SKIP_SLOW_TESTS") != "" {
		t.Skip("waits 10 s")
	}
	e := newEdge(t)
	e.hang = true
	start := time.Now()
	_, err := e.dialer(t).Dial(ctx(t), testName, WebSocket)
	er := asError(t, err)
	if er.Kind != Blocked || er.Reason != "hello_deadline" || er.Cause != CauseAckSignature {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 9*time.Second || d > 12*time.Second {
		t.Fatal(d)
	}
}

func TestDialTLSFailures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *edgeSrv) []dialOpt
		cause string
	}{
		{"wrong certificate name", func(e *edgeSrv) []dialOpt {
			e.cert, e.roots = pki(t, "other.example")
			return nil
		}, CauseTLS},
		{"untrusted root", func(e *edgeSrv) []dialOpt {
			return []dialOpt{func(c *Config) { c.RootCAs = x509.NewCertPool() }}
		}, CauseTLS},
		{"TLS 1.2 only", func(e *edgeSrv) []dialOpt { e.maxVersion = tls.VersionTLS12; return nil }, CauseTLS},
		{"no ALPN", func(e *edgeSrv) []dialOpt { e.alpn = nil; return nil }, CauseALPN},
		{"other ALPN only", func(e *edgeSrv) []dialOpt { e.alpn = []string{"h2"}; return nil }, CauseALPN},
	}
	for _, c := range cases {
		for _, car := range []Carriage{TLS, WebSocket} {
			t.Run(c.name+" "+car.String(), func(t *testing.T) {
				e := newEdge(t)
				opts := c.setup(e)
				_, err := e.dialer(t, opts...).Dial(ctx(t), testName, car)
				if er := asError(t, err); er.Kind != Blocked || er.Cause != c.cause {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDialUpgradeAnswers(t *testing.T) {
	cases := map[string]struct {
		resp  func(key string) string
		cause string
	}{
		"426": {func(string) string { return "HTTP/1.1 426 Upgrade Required\r\nUpgrade: websocket\r\n\r\n" }, CauseSubprotocol},
		"no subprotocol": {func(k string) string {
			return strings.Replace(okResp(k), "Sec-WebSocket-Protocol: sw-tunnel.1\r\n", "", 1)
		}, CauseSubprotocol},
		"404":          {func(string) string { return "HTTP/1.1 404 Not Found\r\n\r\n" }, CauseTLS},
		"wrong accept": {func(string) string { return okResp(rfcKey) }, CauseTLS},
		"extension": {func(k string) string {
			return strings.Replace(okResp(k), "\r\n\r\n", "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n", 1)
		}, CauseTLS},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEdge(t)
			e.upgradeResponse = c.resp
			_, err := e.dialer(t).Dial(ctx(t), testName, WebSocket)
			if er := asError(t, err); er.Kind != Blocked || er.Cause != c.cause {
				t.Fatal(err)
			}
		})
	}
}

func okResp(key string) string {
	return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		acceptValue(key) + "\r\nSec-WebSocket-Protocol: sw-tunnel.1\r\n\r\n"
}

func TestDialConnectFailure(t *testing.T) {
	e := newEdge(t)
	d := e.dialer(t, func(c *Config) {
		c.DialTCP = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	})
	_, err := d.Dial(ctx(t), testName, TLS)
	if er := asError(t, err); er.Kind != Blocked || er.Cause != CauseDial || er.Reason != "connect" {
		t.Fatal(err)
	}
}

// TLS interception: a middlebox with a root the agent trusts terminates
// TLS and opens its own session to the edge. The exporters differ, so the
// edge refuses the Hello.
func TestDialTLSInterceptionFails(t *testing.T) {
	e := newEdge(t)
	mitmCert, mitmRoots := pki(t, "*.seawise.dev")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				in := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{mitmCert}, NextProtos: []string{wire.ALPN, wire.ALPNWebSocket}})
				if in.Handshake() != nil {
					return
				}
				out, err := tls.Dial("tcp", e.ln.Addr().String(), &tls.Config{ServerName: testName, RootCAs: e.roots,
					NextProtos: []string{in.ConnectionState().NegotiatedProtocol}})
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(out, in) }()
				_, _ = io.Copy(in, out)
			}()
		}
	}()
	for _, car := range []Carriage{TLS, WebSocket} {
		d := e.dialer(t, func(c *Config) {
			c.RootCAs = mitmRoots
			c.DialTCP = func(ctx context.Context, n, _ string) (net.Conn, error) {
				var nd net.Dialer
				return nd.DialContext(ctx, n, ln.Addr().String())
			}
		})
		_, err := d.Dial(ctx(t), testName, car)
		if er := asError(t, err); er.Kind != Auth || er.Code != pb.RefuseCode_INVALID_PROOF {
			t.Fatal(car, err)
		}
	}
}
