package wire

import (
	"math"
	"testing"

	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// An input exactly at a message cap passes the size check and fails, if at
// all, for another reason.
func TestExactCapsPassSizeCheck(t *testing.T) {
	for name, f := range map[string]func([]byte) error{
		"hello":     func(b []byte) error { _, err := DecodeHelloBody(b); return err },
		"hello_ack": func(b []byte) error { _, err := DecodeHelloAckBody(b); return err },
		"header":    func(b []byte) error { _, err := DecodeStreamHeader(b, nil); return err },
		"reply":     func(b []byte) error { _, err := DecodeStreamReply(b); return err },
		"relay":     func(b []byte) error { _, err := DecodeRelayPrefix(b, fx.EdgeA); return err },
	} {
		n := map[string]int{"hello": MaxHelloBody, "hello_ack": MaxHelloAckBody, "header": MaxHeader, "reply": MaxReply, "relay": MaxRelayPrefix}[name]
		if err := f(make([]byte, n)); CodeOf(err) == CodeTooLarge {
			t.Errorf("%s: %d bytes refused as too large", name, n)
		}
	}
}

func TestBoundaryValuesAccepted(t *testing.T) {
	p := relayPrefix()
	p.ExpectedEpoch = 1
	if _, err := AppendRelayPrefix(nil, p); err != nil {
		t.Fatal("epoch 1", err)
	}
	a := fx.HelloAckBody([]byte("x"))
	a.MaxStreams = 1
	if _, err := EncodeHelloAckBody(a); err != nil {
		t.Fatal("ack max_streams 1", err)
	}
	ok := map[string]any{
		"min-protocol-minor-max": &pb.ControlMessage_MinVersion{MinVersion: &pb.MinVersion{MinProtocolMinor: math.MaxUint32, MinAgentVersion: "2.0.0", EffectiveAt: 1}},
		"hello-body-1":           &pb.ControlMessage_Hello{Hello: &pb.Hello{Body: []byte{1}, Signature: fx.Bytes("s", 64)}},
		"policy-flags-empty":     &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 1}},
		"result-call-id-max":     &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: MaxCallID, Class: pb.ResultClass_DONE, HttpStatus: 200}},
		"result-call-id-1":       &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: 1, Class: pb.ResultClass_DONE, HttpStatus: 200}},
	}
	for name, body := range ok {
		from := FromEdge
		if name == "hello-body-1" {
			from = FromAgent
		}
		if _, err := EncodeControl(msgWith(1, 1, body), from); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := EncodeControl(msgWith(1, 1, &pb.ControlMessage_HelloAck{HelloAck: &pb.HelloAck{Body: []byte{1}, Signature: fx.Bytes("s", 64)}}), FromEdge); err != nil {
		t.Error("ack body 1", err)
	}
	bad := msgWith(1, 1, &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 1, Flags: "not a jws"}})
	if _, err := EncodeControl(bad, FromEdge); CodeOf(err) != CodeBadValue {
		t.Error("flags not a jws", err)
	}
	r := &pb.DeviceResult{CallId: MaxCallID + 1, Class: pb.ResultClass_DONE, HttpStatus: 200}
	if _, err := EncodeControl(msgWith(1, 1, &pb.ControlMessage_DeviceResult{DeviceResult: r}), FromEdge); CodeOf(err) != CodeBadValue {
		t.Error("result call id over", err)
	}
	_ = proto.Equal
}

func TestErrorStrings(t *testing.T) {
	if (&Error{Code: CodeEmpty}).Error() != "tunnelwire: empty" || (&Error{Code: CodeEmpty, Field: "x"}).Error() != "tunnelwire: empty: x" {
		t.Fatal()
	}
	if FromAgent != 1 || FromEdge != 2 {
		t.Fatal("peer values")
	}
}
