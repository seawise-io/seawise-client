package handshake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

func TestSignedMessageLayout(t *testing.T) {
	ex := fx.ExporterBytes()
	m := HelloMessage(ex, []byte{1, 2})
	want := append(append(append([]byte("seawise-tunnel/1 hello"), 0), ex[:]...), 1, 2)
	if !bytes.Equal(m, want) {
		t.Fatalf("%x", m)
	}
	m = AckMessage(ex, []byte{3})
	want = append(append(append([]byte("seawise-tunnel/1 hello-ack"), 0), ex[:]...), 3)
	if !bytes.Equal(m, want) {
		t.Fatalf("%x", m)
	}
}

func registry(st string) Registry {
	return func(kid string) (Device, bool) {
		if kid != vkeys.KID(fx.DeviceA) {
			return Device{}, false
		}
		return Device{PublicKey: vkeys.Pub(fx.DeviceA), ServerID: fx.UUID(fx.Server1), Status: st}, true
	}
}

func TestSignAndCheckHello(t *testing.T) {
	ex := fx.ExporterBytes()
	h, err := SignHello(vkeys.Key(fx.DeviceA), ex, fx.HelloBody())
	if err != nil {
		t.Fatal(err)
	}
	body, code := CheckHello(h, ex, pb.Transport_TRANSPORT_TLS, registry(StatusActive))
	if code != 0 || !proto.Equal(body, fx.HelloBody()) {
		t.Fatal(code)
	}
	if _, code := CheckHello(h, ex, pb.Transport_TRANSPORT_TLS, registry(StatusRevoked)); code != pb.RefuseCode_KEY_REVOKED {
		t.Fatal(code)
	}
	bad := fx.HelloBody()
	bad.MaxStreams = 0
	if _, err := SignHello(vkeys.Key(fx.DeviceA), ex, bad); wire.CodeOf(err) != wire.CodeBadValue {
		t.Fatal(err)
	}
	if _, code := CheckHello(&pb.Hello{}, ex, pb.Transport_TRANSPORT_TLS, registry(StatusActive)); code != pb.RefuseCode_BAD_REQUEST {
		t.Fatal(code)
	}
	if _, code := CheckHello(nil, ex, pb.Transport_TRANSPORT_TLS, registry(StatusActive)); code != pb.RefuseCode_BAD_REQUEST {
		t.Fatal(code)
	}
}

func sentHello(t *testing.T) Sent {
	h := fx.HelloBody()
	h.Capabilities = []string{"alpha", "beta"}
	b, err := wire.EncodeHelloBody(h)
	if err != nil {
		t.Fatal(err)
	}
	return Sent{Body: b, Hello: h}
}

func edgeKeys(id string) (ed25519.PublicKey, bool) {
	if id == fx.EdgeA || id == fx.EdgeB {
		return vkeys.Pub(id), true
	}
	return nil, false
}

func TestVerifyHelloAck(t *testing.T) {
	ex := fx.ExporterBytes()
	s := sentHello(t)
	body := fx.HelloAckBody(s.Body)
	body.Capabilities = []string{"beta"}
	a, err := SignHelloAck(vkeys.Key(fx.EdgeA), ex, body)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := VerifyHelloAck(a, ex, s, edgeKeys)
	if err != nil || acc.PingInterval != 20*time.Second || acc.PingTimeout != 15*time.Second || !proto.Equal(acc.Ack, body) {
		t.Fatal(err)
	}
	s.Required = []string{"beta"}
	if _, err := VerifyHelloAck(a, ex, s, edgeKeys); err != nil {
		t.Fatal(err)
	}
	s.Required = []string{"alpha"}
	if _, err := VerifyHelloAck(a, ex, s, edgeKeys); CodeOf(err) != CodeEdgeTooOld {
		t.Fatal(err)
	}
	s.Required = nil
	body.MaxStreams = s.Hello.MaxStreams
	a, _ = SignHelloAck(vkeys.Key(fx.EdgeA), ex, body)
	if _, err := VerifyHelloAck(a, ex, s, edgeKeys); err != nil {
		t.Fatal("max_streams equal to the offer refused", err)
	}
	body.ProtocolMinor = s.Hello.ProtocolMinor
	if _, err := VerifyHelloAck(a, ex, s, edgeKeys); err != nil {
		t.Fatal(err)
	}
	body.EdgeId = "edge-x-y-1"
	if _, err := SignHelloAck(vkeys.Key(fx.EdgeA), ex, &pb.HelloAckBody{}); wire.CodeOf(err) == "" {
		t.Fatal(err)
	}
	if _, err := VerifyHelloAck(&pb.HelloAck{Body: a.Body, Signature: a.Signature[:63]}, ex, s, edgeKeys); CodeOf(err) != CodeBadAck {
		t.Fatal(err)
	}
	if _, err := VerifyHelloAck(nil, ex, s, edgeKeys); CodeOf(err) != CodeBadAck {
		t.Fatal(err)
	}
}

func TestClamp(t *testing.T) {
	cases := []struct{ ms, wantI, wantT uint32 }{
		{9999, 10000, 15000}, {10000, 10000, 15000}, {14999, 14999, 15000}, {15000, 15000, 15000},
		{30000, 30000, 30000}, {30001, 30001, 30000}, {60000, 60000, 30000}, {60001, 60000, 30000},
	}
	ex := fx.ExporterBytes()
	s := sentHello(t)
	for _, c := range cases {
		b := fx.HelloAckBody(s.Body)
		b.PingIntervalMs, b.PingTimeoutMs = c.ms, c.ms
		a, _ := SignHelloAck(vkeys.Key(fx.EdgeA), ex, b)
		acc, err := VerifyHelloAck(a, ex, s, edgeKeys)
		if err != nil {
			t.Fatal(err)
		}
		if acc.PingInterval != time.Duration(c.wantI)*time.Millisecond || acc.PingTimeout != time.Duration(c.wantT)*time.Millisecond {
			t.Errorf("%d: %v %v", c.ms, acc.PingInterval, acc.PingTimeout)
		}
	}
}

func TestNegotiate(t *testing.T) {
	minor, caps := Negotiate(2, []string{"c", "a", "b"}, 5, []string{"b", "c"})
	if minor != 2 || len(caps) != 2 || caps[0] != "b" || caps[1] != "c" {
		t.Fatal(minor, caps)
	}
	if _, caps := Negotiate(0, nil, 0, nil); caps == nil || len(caps) != 0 {
		t.Fatal("nil caps")
	}
}

func TestSupersedes(t *testing.T) {
	if Supersedes([]byte{1}, []byte{1}) || !Supersedes([]byte{1}, []byte{2}) {
		t.Fatal()
	}
}

func TestPeerHelloCodec(t *testing.T) {
	h := PeerHello{EdgeID: fx.EdgeA, Nonce: nonce("n")}
	b, err := AppendPeerHello([]byte{9}, h)
	if err != nil || b[0] != 9 || b[1] != byte(len(fx.EdgeA)) || len(b) != 2+len(fx.EdgeA)+32 {
		t.Fatal(err)
	}
	got, err := ReadPeerHello(bytes.NewReader(b[1:]))
	if err != nil || got != h {
		t.Fatal(err)
	}
	if _, err := AppendPeerHello(nil, PeerHello{EdgeID: "x"}); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	if _, err := ReadPeerHello(bytes.NewReader(nil)); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	max := "edge-" + fx.Repeat("a", 54) + "-b-1"
	if len(max) != 63 {
		t.Fatal(len(max))
	}
	b, err = AppendPeerHello(nil, PeerHello{EdgeID: max})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPeerHello(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinal(t *testing.T) {
	for id, want := range map[string]int{"edge-us-east-1": 1, "edge-us-east-12": 12, "edge-a-b-0": 0} {
		if n, ok := Ordinal(id); !ok || n != want {
			t.Error(id, n, ok)
		}
	}
	if n, ok := Ordinal("-5"); !ok || n != 5 {
		t.Error("leading dash")
	}
	for _, id := range []string{"edge", "edge-a-b-x", "edge-a-b-"} {
		if _, ok := Ordinal(id); ok {
			t.Error(id)
		}
	}
	if !Dials("edge-a-b-1", "edge-a-b-2") || Dials("edge-a-b-2", "edge-a-b-1") || Dials("edge-a-b-1", "edge-a-b-1") {
		t.Fatal()
	}
	if Dials("x", "edge-a-b-2") || Dials("edge-a-b-1", "x") {
		t.Fatal("dials with a bad id")
	}
}

func TestCheckPeer(t *testing.T) {
	d := PeerHello{EdgeID: fx.EdgeA, Nonce: nonce("d")}
	a := PeerHello{EdgeID: fx.EdgeB, Nonce: nonce("a")}
	dsig := SignPeer(vkeys.Key(fx.EdgeA), d, a, RoleDialer)
	asig := SignPeer(vkeys.Key(fx.EdgeB), d, a, RoleAcceptor)
	if err := CheckPeer(a, d, RoleAcceptor, dsig, "", edgeKeys); err != nil {
		t.Fatal(err)
	}
	if err := CheckPeer(d, a, RoleDialer, asig, fx.EdgeB, edgeKeys); err != nil {
		t.Fatal(err)
	}
	if err := CheckPeer(d, a, 3, asig, fx.EdgeB, edgeKeys); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	if err := CheckPeer(d, a, 0, asig, fx.EdgeB, edgeKeys); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	if err := CheckPeer(d, a, RoleDialer, asig[:63], fx.EdgeB, edgeKeys); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	if err := CheckPeer(d, PeerHello{EdgeID: "bad"}, RoleDialer, asig, "", edgeKeys); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	none := func(string) (ed25519.PublicKey, bool) { return nil, false }
	if err := CheckPeer(d, a, RoleDialer, asig, fx.EdgeB, none); CodeOf(err) != CodeUnknownEdge {
		t.Fatal(err)
	}
	m := PeerMessage(d, a, RoleAcceptor)
	want := append([]byte("seawise-relay/1\x00"+fx.EdgeA+fx.EdgeB), append(append(d.Nonce[:], a.Nonce[:]...), 2)...)
	if !bytes.Equal(m, want) {
		t.Fatalf("%x", m)
	}
}

func TestErrorString(t *testing.T) {
	if fail(CodeBadAck).Error() != "tunnelwire handshake: bad_ack" || CodeOf(bytes.ErrTooLarge) != "" {
		t.Fatal()
	}
	_ = sha256.Size
}
