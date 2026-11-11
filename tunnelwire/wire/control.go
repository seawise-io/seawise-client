package wire

import (
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// Peer names the sender of a control message.
type Peer int

const (
	FromAgent Peer = iota + 1
	FromEdge
)

func allowedFrom(m *pb.ControlMessage, p Peer) bool {
	switch m.Body.(type) {
	case *pb.ControlMessage_Error:
		return true
	case *pb.ControlMessage_Hello, *pb.ControlMessage_RouteSetAck, *pb.ControlMessage_Ping, *pb.ControlMessage_DeviceCall:
		return p == FromAgent
	default:
		return p == FromEdge
	}
}

// DecodeControl decodes one control message sent by from. A message whose
// kind belongs to a capability this version does not know returns the
// envelope (schema and seq set) with CodeUnsupported: the receiver answers
// Error{UNSUPPORTED} and keeps the session. Every other error is a protocol
// error that closes the session.
func DecodeControl(b []byte, from Peer) (*pb.ControlMessage, error) {
	if len(b) == 0 {
		return nil, fail(CodeEmpty, "control")
	}
	if len(b) > MaxControlMessage {
		return nil, fail(CodeTooLarge, "control")
	}
	m := &pb.ControlMessage{}
	capKind, err := decodeStrict(b, m, true)
	if err != nil {
		return nil, err
	}
	if m.Schema != SchemaVersion {
		return nil, fail(CodeSchema, "schema")
	}
	if m.Seq == 0 {
		return nil, fail(CodeSeq, "seq")
	}
	if capKind {
		return &pb.ControlMessage{Schema: m.Schema, Seq: m.Seq}, fail(CodeUnsupported, "body")
	}
	if m.Body == nil {
		return nil, fail(CodeNoBody, "body")
	}
	if !allowedFrom(m, from) {
		return nil, fail(CodeDirection, "body")
	}
	if err := validateBody(m); err != nil {
		return nil, err
	}
	return m, nil
}

// EncodeControl validates m as its receiver would and marshals it.
func EncodeControl(m *pb.ControlMessage, from Peer) ([]byte, error) {
	b, err := marshal(m)
	if err != nil {
		return nil, fail(CodeBadValue, "control")
	}
	if _, err := DecodeControl(b, from); err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeHelloBody decodes and validates Hello.body.
func DecodeHelloBody(b []byte) (*pb.HelloBody, error) {
	if len(b) == 0 {
		return nil, fail(CodeEmpty, "hello.body")
	}
	if len(b) > MaxHelloBody {
		return nil, fail(CodeTooLarge, "hello.body")
	}
	h := &pb.HelloBody{}
	if _, err := decodeStrict(b, h, false); err != nil {
		return nil, err
	}
	if err := ValidateHelloBody(h); err != nil {
		return nil, err
	}
	return h, nil
}

// EncodeHelloBody validates and marshals a HelloBody.
func EncodeHelloBody(h *pb.HelloBody) ([]byte, error) {
	b, err := marshal(h)
	if err != nil {
		return nil, fail(CodeBadValue, "hello.body")
	}
	if _, err := DecodeHelloBody(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeHelloAckBody decodes and validates HelloAck.body.
func DecodeHelloAckBody(b []byte) (*pb.HelloAckBody, error) {
	if len(b) == 0 {
		return nil, fail(CodeEmpty, "hello_ack.body")
	}
	if len(b) > MaxHelloAckBody {
		return nil, fail(CodeTooLarge, "hello_ack.body")
	}
	h := &pb.HelloAckBody{}
	if _, err := decodeStrict(b, h, false); err != nil {
		return nil, err
	}
	if err := ValidateHelloAckBody(h); err != nil {
		return nil, err
	}
	return h, nil
}

// EncodeHelloAckBody validates and marshals a HelloAckBody.
func EncodeHelloAckBody(h *pb.HelloAckBody) ([]byte, error) {
	b, err := marshal(h)
	if err != nil {
		return nil, fail(CodeBadValue, "hello_ack.body")
	}
	if _, err := DecodeHelloAckBody(b); err != nil {
		return nil, err
	}
	return b, nil
}

// SeqIn checks the seq numbers a receiver sees: 1, 2, 3, ...
type SeqIn struct{ last uint64 }

// Accept returns a CodeSeq error unless seq is the next number.
func (s *SeqIn) Accept(seq uint64) error {
	if seq != s.last+1 {
		return fail(CodeSeq, "seq")
	}
	s.last = seq
	return nil
}

// SeqOut numbers the messages a sender writes.
type SeqOut struct{ last uint64 }

// Next returns the next seq number.
func (s *SeqOut) Next() uint64 {
	s.last++
	return s.last
}
