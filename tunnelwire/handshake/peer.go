package handshake

import (
	"crypto/ed25519"
	"io"
	"strconv"
	"strings"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/edkey"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

const relayContext = "seawise-relay/1"

// Roles in the peer handshake; the role byte ends the signed message.
const (
	RoleDialer   byte = 1
	RoleAcceptor byte = 2
)

// NonceSize is the size of a peer handshake nonce.
const NonceSize = 32

// PeerHello opens the peer handshake in each direction.
type PeerHello struct {
	EdgeID string
	Nonce  [NonceSize]byte
}

// AppendPeerHello appends uint8 length || edge_id || 32-byte nonce.
func AppendPeerHello(dst []byte, h PeerHello) ([]byte, error) {
	if !wire.ValidEdgeID(h.EdgeID) {
		return dst, fail(CodeMalformed)
	}
	dst = append(dst, byte(len(h.EdgeID)))
	dst = append(dst, h.EdgeID...)
	return append(dst, h.Nonce[:]...), nil
}

// ReadPeerHello reads one PeerHello.
func ReadPeerHello(r io.Reader) (PeerHello, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return PeerHello{}, fail(CodeMalformed)
	}
	if n[0] == 0 || int(n[0]) > wire.MaxEdgeID {
		return PeerHello{}, fail(CodeMalformed)
	}
	b := make([]byte, int(n[0])+NonceSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return PeerHello{}, fail(CodeMalformed)
	}
	h := PeerHello{EdgeID: string(b[:n[0]])}
	copy(h.Nonce[:], b[n[0]:])
	if !wire.ValidEdgeID(h.EdgeID) {
		return PeerHello{}, fail(CodeMalformed)
	}
	return h, nil
}

// PeerMessage returns the bytes each side signs:
// "seawise-relay/1" || 0x00 || dialer_id || acceptor_id || dialer_nonce ||
// acceptor_nonce || role. Edge ids are self-delimiting by their syntax.
func PeerMessage(dialer, acceptor PeerHello, role byte) []byte {
	m := make([]byte, 0, len(relayContext)+1+len(dialer.EdgeID)+len(acceptor.EdgeID)+2*NonceSize+1)
	m = append(m, relayContext...)
	m = append(m, 0)
	m = append(m, dialer.EdgeID...)
	m = append(m, acceptor.EdgeID...)
	m = append(m, dialer.Nonce[:]...)
	m = append(m, acceptor.Nonce[:]...)
	return append(m, role)
}

// SignPeer signs the transcript in role.
func SignPeer(priv ed25519.PrivateKey, dialer, acceptor PeerHello, role byte) []byte {
	return ed25519.Sign(priv, PeerMessage(dialer, acceptor, role))
}

// Ordinal returns the trailing number of an edge id.
func Ordinal(edgeID string) (int, bool) {
	i := strings.LastIndexByte(edgeID, '-')
	if i < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(edgeID[i+1:])
	return n, err == nil
}

// Dials reports whether self dials peer: the lower ordinal dials.
func Dials(self, peer string) bool {
	a, okA := Ordinal(self)
	b, okB := Ordinal(peer)
	return okA && okB && a < b
}

// CheckPeer verifies the other side of a peer handshake from self's point
// of view. self carries the fresh nonce self sent; role is self's role;
// expected is the peer edge self dialed, or "" for an acceptor, which takes
// any key-set edge other than itself. sig is the peer's signature in the
// other role.
func CheckPeer(self, peer PeerHello, role byte, sig []byte, expected string, keys EdgeKeys) error {
	if role != RoleDialer && role != RoleAcceptor || !wire.ValidEdgeID(peer.EdgeID) || len(sig) != ed25519.SignatureSize {
		return fail(CodeMalformed)
	}
	if peer.EdgeID == self.EdgeID || expected != "" && peer.EdgeID != expected {
		return fail(CodeWrongPeer)
	}
	if peer.Nonce == self.Nonce {
		return fail(CodeReflected)
	}
	dialer, acceptor, peerRole := self, peer, RoleAcceptor
	if role == RoleAcceptor {
		dialer, acceptor, peerRole = peer, self, RoleDialer
	}
	if !Dials(dialer.EdgeID, acceptor.EdgeID) {
		return fail(CodeDialOrder)
	}
	pub, ok := keys(peer.EdgeID)
	if !ok {
		return fail(CodeUnknownEdge)
	}
	if !edkey.Verify(pub, PeerMessage(dialer, acceptor, peerRole), sig) {
		return fail(CodeBadSignature)
	}
	return nil
}
