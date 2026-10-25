package handshake

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func FuzzPeerHandshake(f *testing.F) {
	d := PeerHello{EdgeID: fx.EdgeA, Nonce: nonce("d")}
	a := PeerHello{EdgeID: fx.EdgeB, Nonce: nonce("a")}
	dh, _ := AppendPeerHello(nil, d)
	f.Add(dh, SignPeer(vkeys.Key(fx.EdgeA), d, a, RoleDialer))
	f.Add([]byte{0}, []byte{})
	keys := func(id string) (ed25519.PublicKey, bool) {
		if id == fx.EdgeA || id == fx.EdgeB {
			return vkeys.Pub(id), true
		}
		return nil, false
	}
	f.Fuzz(func(t *testing.T, hello, sig []byte) {
		peer, err := ReadPeerHello(bytes.NewReader(hello))
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatal("uncoded")
			}
			return
		}
		err = CheckPeer(a, peer, RoleAcceptor, sig, "", keys)
		if err == nil {
			if !ed25519.Verify(vkeys.Pub(peer.EdgeID), PeerMessage(peer, a, RoleDialer), sig) || peer.EdgeID != fx.EdgeA {
				t.Fatal("accepted an unverified dialer")
			}
		} else if CodeOf(err) == "" {
			t.Fatal("uncoded")
		}
	})
}

func FuzzHello(f *testing.F) {
	ex := fx.ExporterBytes()
	h, _ := SignHello(vkeys.Key(fx.DeviceA), ex, fx.HelloBody())
	b, _ := proto.Marshal(h)
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		h := &pb.Hello{}
		if proto.Unmarshal(in, h) != nil {
			return
		}
		body, code := CheckHello(h, ex, pb.Transport_TRANSPORT_TLS, registry(StatusActive))
		if code == 0 && (body == nil || !ed25519.Verify(vkeys.Pub(fx.DeviceA), HelloMessage(ex, h.Body), h.Signature)) {
			t.Fatal("accepted an unverified hello")
		}
	})
}

func FuzzHelloAck(f *testing.F) {
	ex := fx.ExporterBytes()
	s := Sent{Body: marshal(fx.HelloBody()), Hello: fx.HelloBody()}
	a, _ := SignHelloAck(vkeys.Key(fx.EdgeA), ex, fx.HelloAckBody(s.Body))
	f.Add(marshal(a))
	f.Fuzz(func(t *testing.T, in []byte) {
		a := &pb.HelloAck{}
		if proto.Unmarshal(in, a) != nil {
			return
		}
		acc, err := VerifyHelloAck(a, ex, s, edgeKeys)
		if err == nil && (acc.Ack.MaxStreams > s.Hello.MaxStreams || !ed25519.Verify(vkeys.Pub(acc.Ack.EdgeId), AckMessage(ex, a.Body), a.Signature)) {
			t.Fatal("accepted a bad ack")
		}
		if err != nil && CodeOf(err) == "" {
			t.Fatal("uncoded")
		}
	})
}
