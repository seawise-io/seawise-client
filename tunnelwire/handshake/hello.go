// Package handshake implements the seawise-tunnel/1 Hello and HelloAck
// signatures, the edge's Hello checks, capability negotiation, and the
// mutual authentication between peer edges.
package handshake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/edkey"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

const (
	helloContext = "seawise-tunnel/1 hello"
	ackContext   = "seawise-tunnel/1 hello-ack"
)

// ExporterLabel and ExporterLength select the RFC 9266 tls-exporter value.
const (
	ExporterLabel  = "EXPORTER-Channel-Binding"
	ExporterLength = 32
)

// Code classifies a handshake failure on the agent side or between edges.
type Code string

const (
	CodeBadAck         Code = "bad_ack"
	CodeUnknownEdge    Code = "unknown_edge"
	CodeBadSignature   Code = "bad_signature"
	CodeDigestMismatch Code = "digest_mismatch"
	CodeBadNegotiation Code = "bad_negotiation"
	CodeEdgeTooOld     Code = "edge_too_old"
	CodeMalformed      Code = "malformed"
	CodeWrongPeer      Code = "wrong_peer"
	CodeReflected      Code = "reflected_nonce"
	CodeDialOrder      Code = "dial_order"
)

// Error is a handshake error.
type Error struct{ Code Code }

func (e *Error) Error() string { return "tunnelwire handshake: " + string(e.Code) }

func fail(c Code) error { return &Error{Code: c} }

// CodeOf returns the code of a handshake error, or "".
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func signedMessage(context string, exporter [32]byte, body []byte) []byte {
	m := make([]byte, 0, len(context)+1+len(exporter)+len(body))
	m = append(m, context...)
	m = append(m, 0)
	m = append(m, exporter[:]...)
	return append(m, body...)
}

// HelloMessage returns the bytes the device key signs.
func HelloMessage(exporter [32]byte, body []byte) []byte {
	return signedMessage(helloContext, exporter, body)
}

// AckMessage returns the bytes the edge key signs.
func AckMessage(exporter [32]byte, body []byte) []byte {
	return signedMessage(ackContext, exporter, body)
}

// SignHello encodes body and signs it for the connection with exporter.
func SignHello(priv ed25519.PrivateKey, exporter [32]byte, body *pb.HelloBody) (*pb.Hello, error) {
	b, err := wire.EncodeHelloBody(body)
	if err != nil {
		return nil, err
	}
	return &pb.Hello{Body: b, Signature: ed25519.Sign(priv, HelloMessage(exporter, b))}, nil
}

// SignHelloAck encodes body and signs it with the edge key.
func SignHelloAck(priv ed25519.PrivateKey, exporter [32]byte, body *pb.HelloAckBody) (*pb.HelloAck, error) {
	b, err := wire.EncodeHelloAckBody(body)
	if err != nil {
		return nil, err
	}
	return &pb.HelloAck{Body: b, Signature: ed25519.Sign(priv, AckMessage(exporter, b))}, nil
}

// Device registry statuses.
const (
	StatusActive       = "active"
	StatusRevoked      = "revoked"
	StatusCompromised  = "compromised"
	StatusPending      = "pending"
	StatusEnrolPending = "enrol_pending"
)

// Device is a device-registry entry as the edge's snapshot holds it.
type Device struct {
	PublicKey ed25519.PublicKey
	ServerID  []byte
	Status    string
}

// Registry looks a device up by key id.
type Registry func(keyID string) (Device, bool)

// CheckHello runs the edge's Hello checks that need no policy: decoding,
// transport, key lookup, signature over the exporter, and key status. It
// returns the body and REFUSE_UNSPECIFIED when the Hello passes. An unknown
// key, a bad signature and a server mismatch all give INVALID_PROOF; the
// status is looked at only after the signature verified.
func CheckHello(h *pb.Hello, exporter [32]byte, observed pb.Transport, reg Registry) (*pb.HelloBody, pb.RefuseCode) {
	if len(h.GetSignature()) != wire.SignatureSize {
		return nil, pb.RefuseCode_BAD_REQUEST
	}
	body, err := wire.DecodeHelloBody(h.GetBody())
	if err != nil || body.Transport != observed {
		return nil, pb.RefuseCode_BAD_REQUEST
	}
	dev, ok := reg(body.KeyId)
	if !ok || edkey.Check(dev.PublicKey) != nil || edkey.KeyID(dev.PublicKey) != body.KeyId ||
		!bytes.Equal(dev.ServerID, body.ServerId) ||
		!edkey.Verify(dev.PublicKey, HelloMessage(exporter, h.Body), h.Signature) {
		return nil, pb.RefuseCode_INVALID_PROOF
	}
	switch dev.Status {
	case StatusActive:
		return body, pb.RefuseCode_REFUSE_UNSPECIFIED
	case StatusRevoked, StatusCompromised:
		return nil, pb.RefuseCode_KEY_REVOKED
	case StatusPending, StatusEnrolPending:
		return nil, pb.RefuseCode_NOT_ENROLLED
	}
	return nil, pb.RefuseCode_INVALID_PROOF
}

// Negotiate returns min(agent, edge) and the sorted intersection of the
// capability lists. Unknown capability strings drop out.
func Negotiate(agentMinor uint32, agentCaps []string, edgeMinor uint32, edgeCaps []string) (uint32, []string) {
	caps := []string{}
	for _, c := range agentCaps {
		if slices.Contains(edgeCaps, c) {
			caps = append(caps, c)
		}
	}
	slices.Sort(caps)
	return min(agentMinor, edgeMinor), caps
}

// Supersedes reports whether a new session must send the older session of
// the same server Drain{SUPERSEDED, STOP}. A session of the same run is the
// agent's own make before break and gets no message.
func Supersedes(oldRunID, newRunID []byte) bool { return !bytes.Equal(oldRunID, newRunID) }

// Ping bounds the agent applies to the edge's values.
const (
	MinPingInterval = 10 * time.Second
	MaxPingInterval = 60 * time.Second
	MinPingTimeout  = 15 * time.Second
	MaxPingTimeout  = 30 * time.Second
)

// EdgeKeys returns the key-set edge key named edgeID (status active or
// next).
type EdgeKeys func(edgeID string) (ed25519.PublicKey, bool)

// Sent is what the agent sent in its Hello.
type Sent struct {
	Body     []byte        // Hello.body as sent
	Hello    *pb.HelloBody // decoded Body
	Required []string      // capabilities the agent cannot work without
}

// Accepted is a verified HelloAck with the ping values clamped.
type Accepted struct {
	Ack          *pb.HelloAckBody
	PingInterval time.Duration
	PingTimeout  time.Duration
}

// VerifyHelloAck checks a HelloAck on the agent side: the edge signature
// over this connection's exporter by the key-set key of body.edge_id, the
// digest of the Hello as sent, and that the negotiated values are within
// what the agent offered. A missing required capability is
// CodeEdgeTooOld.
func VerifyHelloAck(a *pb.HelloAck, exporter [32]byte, sent Sent, keys EdgeKeys) (*Accepted, error) {
	body, err := wire.DecodeHelloAckBody(a.GetBody())
	if err != nil || len(a.GetSignature()) != wire.SignatureSize {
		return nil, fail(CodeBadAck)
	}
	pub, ok := keys(body.EdgeId)
	if !ok {
		return nil, fail(CodeUnknownEdge)
	}
	if !edkey.Verify(pub, AckMessage(exporter, a.Body), a.Signature) {
		return nil, fail(CodeBadSignature)
	}
	d := sha256.Sum256(sent.Body)
	if !bytes.Equal(d[:], body.OfferedDigest) {
		return nil, fail(CodeDigestMismatch)
	}
	if body.ProtocolMinor > sent.Hello.ProtocolMinor || body.MaxStreams > sent.Hello.MaxStreams {
		return nil, fail(CodeBadNegotiation)
	}
	for _, c := range body.Capabilities {
		if !slices.Contains(sent.Hello.Capabilities, c) {
			return nil, fail(CodeBadNegotiation)
		}
	}
	for _, c := range sent.Required {
		if !slices.Contains(body.Capabilities, c) {
			return nil, fail(CodeEdgeTooOld)
		}
	}
	return &Accepted{
		Ack:          body,
		PingInterval: clamp(time.Duration(body.PingIntervalMs)*time.Millisecond, MinPingInterval, MaxPingInterval),
		PingTimeout:  clamp(time.Duration(body.PingTimeoutMs)*time.Millisecond, MinPingTimeout, MaxPingTimeout),
	}, nil
}

func clamp(v, lo, hi time.Duration) time.Duration { return max(lo, min(v, hi)) }
