package wire

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"reflect"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

type vcase struct {
	Name    string         `json:"name"`
	Input   string         `json:"input"`
	Context map[string]any `json:"context,omitempty"`
	Expect  string         `json:"expect"`
	Result  any            `json:"result,omitempty"`
}

type vfile struct {
	Format string  `json:"format"`
	Note   string  `json:"note"`
	Cases  []vcase `json:"cases"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustMarshal(m proto.Message) []byte {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// msgWith builds an envelope around a oneof body value.
func msgWith(schema uint32, seq uint64, body any) *pb.ControlMessage {
	m := &pb.ControlMessage{Schema: schema, Seq: seq}
	reflect.ValueOf(m).Elem().FieldByName("Body").Set(reflect.ValueOf(body))
	return m
}

func frame(msgs ...[]byte) []byte {
	var out []byte
	for _, m := range msgs {
		out = binary.BigEndian.AppendUint32(out, uint32(len(m)))
		out = append(out, m...)
	}
	return out
}

func env(seq uint64, body any) []byte {
	return mustMarshal(msgWith(1, seq, body))
}

// rawEnv builds an envelope from schema, seq and raw trailing fields.
func rawEnv(schema, seq uint64, tail []byte) []byte {
	var b []byte
	if schema != 0 {
		b = protowire.AppendTag(b, 1, protowire.VarintType)
		b = protowire.AppendVarint(b, schema)
	}
	if seq != 0 {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, seq)
	}
	return append(b, tail...)
}

func bytesField(num protowire.Number, v []byte) []byte {
	b := protowire.AppendTag(nil, num, protowire.BytesType)
	return protowire.AppendBytes(b, v)
}

func varintField(num protowire.Number, v uint64) []byte {
	b := protowire.AppendTag(nil, num, protowire.VarintType)
	return protowire.AppendVarint(b, v)
}

func validHelloBodyBytes() []byte { return mustMarshal(fx.HelloBody()) }

func agentKinds() map[string]any {
	return map[string]any{
		"hello":         &pb.ControlMessage_Hello{Hello: &pb.Hello{Body: validHelloBodyBytes(), Signature: fx.Bytes("sig", 64)}},
		"route_set_ack": &pb.ControlMessage_RouteSetAck{RouteSetAck: &pb.RouteSetAck{Version: 1}},
		"ping":          &pb.ControlMessage_Ping{Ping: &pb.Ping{Nonce: 7}},
		"device_call":   &pb.ControlMessage_DeviceCall{DeviceCall: deviceCall()},
		"error":         &pb.ControlMessage_Error{Error: &pb.Error{Code: pb.ErrorCode_UNSUPPORTED, Detail: "unsupported"}},
	}
}

func deviceCall() *pb.DeviceCall {
	return &pb.DeviceCall{CallId: 1, IdempotencyKey: fx.Bytes("idem-1", 16), Method: pb.DeviceMethod_REGISTER_APPS, Dpop: fx.JWS(400), Body: []byte(`{"apps":[]}`)}
}

func deviceResult() *pb.DeviceResult {
	return &pb.DeviceResult{CallId: 1, Class: pb.ResultClass_DONE, HttpStatus: 200, Body: []byte(`{"ok":true}`), DpopNonce: "n1.AAAAAQ.c2VydmVyLW5vbmNl"}
}

func edgeKinds() map[string]any {
	ack := mustMarshal(fx.HelloAckBody(validHelloBodyBytes()))
	return map[string]any{
		"hello_ack":      &pb.ControlMessage_HelloAck{HelloAck: &pb.HelloAck{Body: ack, Signature: fx.Bytes("sig", 64)}},
		"hello_refuse":   &pb.ControlMessage_HelloRefuse{HelloRefuse: &pb.HelloRefuse{Code: pb.RefuseCode_INVALID_PROOF, Detail: "invalid proof"}},
		"route_set":      &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: fx.JWS(1000), SignedTime: fx.JWS(300)}},
		"pong":           &pb.ControlMessage_Pong{Pong: &pb.Pong{Nonce: 7, PolicyVersion: 3}},
		"drain":          &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_ROLLOUT, DeadlineMs: 30000, Action: pb.DrainAction_RECONNECT}},
		"revoke":         &pb.ControlMessage_Revoke{Revoke: &pb.Revoke{Scope: pb.RevokeScope_DEVICE, Detail: "device revoked"}},
		"min_version":    &pb.ControlMessage_MinVersion{MinVersion: &pb.MinVersion{MinProtocolMinor: 0, MinAgentVersion: "2.0.0", EffectiveAt: 1793000000}},
		"policy_version": &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 1, SnapshotVersion: 9, SnapshotGeneration: 2, KeysetVersion: 5, Flags: fx.JWS(500)}},
		"device_result":  &pb.ControlMessage_DeviceResult{DeviceResult: deviceResult()},
		"error":          &pb.ControlMessage_Error{Error: &pb.Error{Code: pb.ErrorCode_PROTOCOL, Detail: "protocol error"}},
	}
}

var kindOrderAgent = []string{"hello", "route_set_ack", "ping", "device_call", "error"}
var kindOrderEdge = []string{"hello_ack", "hello_refuse", "route_set", "pong", "drain", "revoke", "min_version", "policy_version", "device_result", "error"}

type step struct {
	Kind string `json:"kind"`
	Seq  uint64 `json:"seq"`
}

func genControlFrames() vfile {
	var cs []vcase
	add := func(name string, input []byte, from, layer, expect string, result any) {
		cs = append(cs, vcase{Name: name, Input: b64(input), Context: map[string]any{"from": from, "layer": layer}, Expect: expect, Result: result})
	}
	msg := func(name, from string, body any, expect string) {
		in := frame(env(1, body))
		if expect == "ok" {
			add(name, in, from, "message", "ok", []step{{Kind: protoKind(body), Seq: 1}})
			return
		}
		add(name, in, from, "message", expect, nil)
	}

	// Framing.
	add("frame-length-0", []byte{0, 0, 0, 0}, "agent", "frame", "empty", nil)
	add("frame-length-1", frame([]byte{0x08}), "agent", "frame", "ok", nil)
	add("frame-length-1-message", frame([]byte{0x08}), "agent", "message", "malformed", nil)
	big := mustMarshal(&pb.ControlMessage{Schema: 1, Seq: 1, Body: &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: fx.JWS(65536 - 12)}}})
	if len(big) != 65536 {
		panic(len(big))
	}
	add("frame-length-65536", frame(big), "edge", "frame", "ok", nil)
	add("frame-length-65536-message", frame(big), "edge", "message", "too_large", nil)
	add("frame-length-65537", []byte{0, 1, 0, 1}, "edge", "frame", "too_large", nil)
	add("frame-length-max-uint32", []byte{0xff, 0xff, 0xff, 0xff}, "edge", "frame", "too_large", nil)
	ping := env(1, agentKinds()["ping"])
	add("partial-length", frame(ping)[:3], "agent", "frame", "truncated", nil)
	add("partial-body", frame(ping)[:6], "agent", "frame", "truncated", nil)
	add("partial-second-frame", append(frame(ping), frame(env(2, agentKinds()["ping"]))[:5]...), "agent", "frame", "truncated", nil)

	// One valid frame of every kind.
	for _, k := range kindOrderAgent {
		msg("valid-agent-"+k, "agent", agentKinds()[k], "ok")
	}
	for _, k := range kindOrderEdge {
		msg("valid-edge-"+k, "edge", edgeKinds()[k], "ok")
	}

	// Sequence numbers.
	p := func(seq uint64) []byte { return env(seq, agentKinds()["ping"]) }
	add("seq-1-2-3", frame(p(1), p(2), p(3)), "agent", "message", "ok", []step{{"ping", 1}, {"ping", 2}, {"ping", 3}})
	add("seq-gap", frame(p(1), p(3)), "agent", "message", "seq", nil)
	add("seq-repeat", frame(p(1), p(1)), "agent", "message", "seq", nil)
	add("seq-starts-at-2", frame(p(2)), "agent", "message", "seq", nil)
	add("seq-zero", frame(rawEnv(1, 0, bytesField(15, nil))), "agent", "message", "seq", nil)

	// Envelope.
	pingBody := bytesField(15, mustMarshal(&pb.Ping{Nonce: 7}))
	add("schema-0", frame(rawEnv(0, 1, pingBody)), "agent", "message", "schema", nil)
	add("schema-2", frame(rawEnv(2, 1, pingBody)), "agent", "message", "schema", nil)
	add("empty-oneof", frame(rawEnv(1, 1, nil)), "agent", "message", "no_body", nil)
	add("two-bodies", frame(rawEnv(1, 1, append(append([]byte{}, pingBody...), bytesField(14, mustMarshal(&pb.RouteSetAck{Version: 1}))...))), "agent", "message", "multiple_bodies", nil)
	add("same-body-twice", frame(rawEnv(1, 1, append(append([]byte{}, pingBody...), pingBody...))), "agent", "message", "duplicate_field", nil)
	add("capability-kind-24", frame(rawEnv(1, 1, bytesField(24, []byte{0x08, 0x01}))), "agent", "message", "unsupported", []step{{"", 1}})
	add("capability-kind-99", frame(rawEnv(1, 1, varintField(99, 1))), "agent", "message", "unsupported", []step{{"", 1}})
	add("capability-kind-with-body", frame(rawEnv(1, 1, append(append([]byte{}, pingBody...), bytesField(24, nil)...))), "agent", "message", "multiple_bodies", nil)
	add("unknown-field-100", frame(rawEnv(1, 1, append(append([]byte{}, pingBody...), varintField(100, 1)...))), "agent", "message", "unknown_field", nil)
	add("unknown-field-3", frame(rawEnv(1, 1, append(append([]byte{}, pingBody...), varintField(3, 1)...))), "agent", "message", "unknown_field", nil)
	add("unknown-field-in-body", frame(rawEnv(1, 1, bytesField(15, append(varintField(1, 7), varintField(2, 1)...)))), "agent", "message", "unknown_field", nil)
	add("duplicate-seq", frame(append(rawEnv(1, 1, pingBody), varintField(2, 1)...)), "agent", "message", "duplicate_field", nil)
	add("wire-type-schema-as-bytes", frame(append(bytesField(1, []byte{1}), append(varintField(2, 1), pingBody...)...)), "agent", "message", "wire_type", nil)
	add("wire-type-body-as-varint", frame(rawEnv(1, 1, varintField(15, 1))), "agent", "message", "wire_type", nil)
	add("non-minimal-varint", frame(append([]byte{0x08, 0x81, 0x00}, append(varintField(2, 1), pingBody...)...)), "agent", "message", "malformed", nil)
	add("non-minimal-tag", frame(append([]byte{0x88, 0x00, 0x01}, append(varintField(2, 1), pingBody...)...)), "agent", "message", "malformed", nil)
	add("non-minimal-length", frame(rawEnv(1, 1, []byte{0x7a, 0x82, 0x00, 0x08, 0x07})), "agent", "message", "malformed", nil)
	add("length-past-end", frame(rawEnv(1, 1, []byte{0x7a, 0x05, 0x08})), "agent", "message", "malformed", nil)
	add("schema-uint32-overflow", frame(rawEnv(1<<32+1, 1, pingBody)), "agent", "message", "bad_value", nil)
	add("group-wire-type", frame(rawEnv(1, 1, []byte{0x7b, 0x7c})), "agent", "message", "wire_type", nil)
	drainRaw := func(reason uint64) []byte {
		d := append(varintField(1, reason), varintField(2, 30000)...)
		return frame(rawEnv(1, 1, bytesField(17, d)))
	}
	add("enum-unknown-value", drainRaw(99), "edge", "message", "bad_value", nil)
	add("enum-negative", drainRaw(math.MaxUint64), "edge", "message", "bad_value", nil)
	add("enum-int32-overflow", drainRaw(1<<32+1), "edge", "message", "bad_value", nil)
	add("reserved-field-5", frame(rawEnv(1, 1, bytesField(20, append(varintField(1, 1), varintField(5, 1)...)))), "edge", "message", "unknown_field", nil)
	add("invalid-utf8", frame(rawEnv(1, 1, bytesField(23, append(varintField(1, 1), bytesField(2, []byte{0xff})...)))), "agent", "message", "bad_value", nil)

	// Direction.
	add("hello-from-edge", frame(env(1, agentKinds()["hello"])), "edge", "message", "direction", nil)
	add("hello-ack-from-agent", frame(env(1, edgeKinds()["hello_ack"])), "agent", "message", "direction", nil)
	add("device-result-from-agent", frame(env(1, edgeKinds()["device_result"])), "agent", "message", "direction", nil)
	add("device-call-from-edge", frame(env(1, agentKinds()["device_call"])), "edge", "message", "direction", nil)

	// Caps of every field.
	hello := func(body, sig []byte) any {
		return &pb.ControlMessage_Hello{Hello: &pb.Hello{Body: body, Signature: sig}}
	}
	sig := fx.Bytes("sig", 64)
	msg("hello-body-4096", "agent", hello(fx.Bytes("b", 4096), sig), "ok")
	msg("hello-body-4097", "agent", hello(fx.Bytes("b", 4097), sig), "too_large")
	msg("hello-body-empty", "agent", hello(nil, sig), "bad_value")
	msg("hello-signature-63", "agent", hello(fx.Bytes("b", 10), sig[:63]), "bad_value")
	msg("hello-signature-65", "agent", hello(fx.Bytes("b", 10), fx.Bytes("s", 65)), "too_large")
	ack := func(body []byte) any {
		return &pb.ControlMessage_HelloAck{HelloAck: &pb.HelloAck{Body: body, Signature: sig}}
	}
	msg("hello-ack-body-2048", "edge", ack(fx.Bytes("b", 2048)), "ok")
	msg("hello-ack-body-2049", "edge", ack(fx.Bytes("b", 2049)), "too_large")
	refuse := func(r *pb.HelloRefuse) any {
		return &pb.ControlMessage_HelloRefuse{HelloRefuse: r}
	}
	msg("refuse-detail-128", "edge", refuse(&pb.HelloRefuse{Code: 1, Detail: fx.Repeat("x", 128)}), "ok")
	msg("refuse-detail-129", "edge", refuse(&pb.HelloRefuse{Code: 1, Detail: fx.Repeat("x", 129)}), "too_large")
	msg("refuse-detail-control-char", "edge", refuse(&pb.HelloRefuse{Code: 1, Detail: "bad\nline"}), "bad_value")
	msg("refuse-unspecified", "edge", refuse(&pb.HelloRefuse{Code: 0}), "bad_value")
	msg("refuse-retry-max", "edge", refuse(&pb.HelloRefuse{Code: pb.RefuseCode_EDGE_NOT_READY, RetryAfterMs: 86400000}), "ok")
	msg("refuse-retry-over", "edge", refuse(&pb.HelloRefuse{Code: pb.RefuseCode_EDGE_NOT_READY, RetryAfterMs: 86400001}), "bad_value")
	msg("refuse-overloaded-without-retry", "edge", refuse(&pb.HelloRefuse{Code: pb.RefuseCode_OVERLOADED}), "bad_value")
	msg("refuse-overloaded-with-retry", "edge", refuse(&pb.HelloRefuse{Code: pb.RefuseCode_OVERLOADED, RetryAfterMs: 5000}), "ok")
	rs := func(jws, st string) any {
		return &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: jws, SignedTime: st}}
	}
	msg("route-set-jws-61440", "edge", rs(fx.JWS(61440), fx.JWS(1024)), "ok")
	msg("route-set-jws-61441", "edge", rs(fx.JWS(61441), ""), "too_large")
	msg("route-set-jws-empty", "edge", rs("", ""), "bad_value")
	msg("route-set-jws-not-compact", "edge", rs("a.b", ""), "bad_value")
	msg("route-set-signed-time-1025", "edge", rs(fx.JWS(100), fx.JWS(1025)), "too_large")
	msg("route-set-ack-version-0", "agent", &pb.ControlMessage_RouteSetAck{RouteSetAck: &pb.RouteSetAck{}}, "bad_value")
	drain := func(d *pb.Drain) any { return &pb.ControlMessage_Drain{Drain: d} }
	msg("drain-deadline-999", "edge", drain(&pb.Drain{Reason: 1, DeadlineMs: 999}), "bad_value")
	msg("drain-deadline-1000", "edge", drain(&pb.Drain{Reason: 1, DeadlineMs: 1000}), "ok")
	msg("drain-deadline-120000", "edge", drain(&pb.Drain{Reason: 1, DeadlineMs: 120000}), "ok")
	msg("drain-deadline-120001", "edge", drain(&pb.Drain{Reason: 1, DeadlineMs: 120001}), "bad_value")
	msg("drain-reason-unspecified", "edge", drain(&pb.Drain{DeadlineMs: 1000}), "bad_value")
	msg("drain-stop-superseded", "edge", drain(&pb.Drain{Reason: pb.DrainReason_SUPERSEDED, DeadlineMs: 1000, Action: pb.DrainAction_STOP}), "ok")
	msg("drain-stop-not-superseded", "edge", drain(&pb.Drain{Reason: pb.DrainReason_ROLLOUT, DeadlineMs: 1000, Action: pb.DrainAction_STOP}), "bad_value")
	revoke := func(r *pb.Revoke) any { return &pb.ControlMessage_Revoke{Revoke: r} }
	msg("revoke-app", "edge", revoke(&pb.Revoke{Scope: pb.RevokeScope_APP, AppId: fx.UUID(fx.App1)}), "ok")
	msg("revoke-app-15", "edge", revoke(&pb.Revoke{Scope: pb.RevokeScope_APP, AppId: fx.Bytes("a", 15)}), "bad_value")
	msg("revoke-app-17", "edge", revoke(&pb.Revoke{Scope: pb.RevokeScope_APP, AppId: fx.Bytes("a", 17)}), "too_large")
	msg("revoke-app-missing", "edge", revoke(&pb.Revoke{Scope: pb.RevokeScope_APP}), "bad_value")
	msg("revoke-device-with-app", "edge", revoke(&pb.Revoke{Scope: pb.RevokeScope_DEVICE, AppId: fx.UUID(fx.App1)}), "bad_value")
	msg("revoke-unspecified", "edge", revoke(&pb.Revoke{}), "bad_value")
	mv := func(v string, at int64) any {
		return &pb.ControlMessage_MinVersion{MinVersion: &pb.MinVersion{MinAgentVersion: v, EffectiveAt: at}}
	}
	msg("min-version-prerelease", "edge", mv("2.0.0-rc.1", 1), "ok")
	msg("min-version-build-metadata", "edge", mv("2.0.0+build", 1), "bad_value")
	msg("min-version-leading-zero", "edge", mv("2.01.0", 1), "bad_value")
	msg("min-version-33", "edge", mv("2.0.0-"+fx.Repeat("a", 27), 1), "too_large")
	msg("min-version-no-effective-at", "edge", mv("2.0.0", 0), "bad_value")
	pv := func(v uint64, flags string) any {
		return &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: v, Flags: flags}}
	}
	msg("policy-flags-16384", "edge", pv(1, fx.JWS(16384)), "ok")
	msg("policy-flags-16385", "edge", pv(1, fx.JWS(16385)), "too_large")
	msg("policy-version-0", "edge", pv(0, ""), "bad_value")
	call := func(f func(*pb.DeviceCall)) any {
		c := deviceCall()
		f(c)
		return &pb.ControlMessage_DeviceCall{DeviceCall: c}
	}
	msg("call-id-0", "agent", call(func(c *pb.DeviceCall) { c.CallId = 0 }), "bad_value")
	msg("call-id-max", "agent", call(func(c *pb.DeviceCall) { c.CallId = MaxCallID }), "ok")
	msg("call-id-over", "agent", call(func(c *pb.DeviceCall) { c.CallId = MaxCallID + 1 }), "bad_value")
	msg("call-idempotency-15", "agent", call(func(c *pb.DeviceCall) { c.IdempotencyKey = c.IdempotencyKey[:15] }), "bad_value")
	msg("call-idempotency-missing", "agent", call(func(c *pb.DeviceCall) { c.IdempotencyKey = nil }), "bad_value")
	msg("call-method-unspecified", "agent", call(func(c *pb.DeviceCall) { c.Method = 0 }), "bad_value")
	msg("call-path-suffix-without-parameter", "agent", call(func(c *pb.DeviceCall) { c.PathSuffix = "app-1" }), "bad_value")
	msg("call-path-suffix-257", "agent", call(func(c *pb.DeviceCall) { c.PathSuffix = fx.Repeat("a", 257) }), "too_large")
	msg("call-dpop-2048", "agent", call(func(c *pb.DeviceCall) { c.Dpop = fx.JWS(2048) }), "ok")
	msg("call-dpop-2049", "agent", call(func(c *pb.DeviceCall) { c.Dpop = fx.JWS(2049) }), "too_large")
	msg("call-dpop-missing", "agent", call(func(c *pb.DeviceCall) { c.Dpop = "" }), "bad_value")
	msg("call-body-57344", "agent", call(func(c *pb.DeviceCall) { c.Body = fx.Pad(nil, 'x', 57344) }), "ok")
	msg("call-body-57345", "agent", call(func(c *pb.DeviceCall) { c.Body = fx.Pad(nil, 'x', 57345) }), "too_large")
	res := func(f func(*pb.DeviceResult)) any {
		r := deviceResult()
		f(r)
		return &pb.ControlMessage_DeviceResult{DeviceResult: r}
	}
	msg("result-status-99", "edge", res(func(r *pb.DeviceResult) { r.HttpStatus = 99 }), "bad_value")
	msg("result-status-100", "edge", res(func(r *pb.DeviceResult) { r.HttpStatus = 100 }), "ok")
	msg("result-status-599", "edge", res(func(r *pb.DeviceResult) { r.HttpStatus = 599 }), "ok")
	msg("result-status-600", "edge", res(func(r *pb.DeviceResult) { r.HttpStatus = 600 }), "bad_value")
	msg("result-unavailable", "edge", res(func(r *pb.DeviceResult) {
		r.Class, r.HttpStatus, r.Body, r.RetryAfterMs = pb.ResultClass_UNAVAILABLE, 0, nil, 2000
	}), "ok")
	msg("result-unavailable-with-status", "edge", res(func(r *pb.DeviceResult) { r.Class = pb.ResultClass_UNAVAILABLE }), "bad_value")
	msg("result-class-unspecified", "edge", res(func(r *pb.DeviceResult) { r.Class = 0 }), "bad_value")
	msg("result-body-57345", "edge", res(func(r *pb.DeviceResult) { r.Body = fx.Pad(nil, 'x', 57345) }), "too_large")
	msg("result-nonce-256", "edge", res(func(r *pb.DeviceResult) { r.DpopNonce = fx.Repeat("n", 256) }), "ok")
	msg("result-nonce-257", "edge", res(func(r *pb.DeviceResult) { r.DpopNonce = fx.Repeat("n", 257) }), "too_large")
	msg("result-nonce-bad-char", "edge", res(func(r *pb.DeviceResult) { r.DpopNonce = "a\"b" }), "bad_value")
	msg("result-retry-300000", "edge", res(func(r *pb.DeviceResult) { r.RetryAfterMs = 300000 }), "ok")
	msg("result-retry-300001", "edge", res(func(r *pb.DeviceResult) { r.RetryAfterMs = 300001 }), "bad_value")
	msg("error-unspecified", "agent", &pb.ControlMessage_Error{Error: &pb.Error{}}, "bad_value")
	msg("error-detail-129", "agent", &pb.ControlMessage_Error{Error: &pb.Error{Code: 1, Detail: fx.Repeat("x", 129)}}, "too_large")

	return vfile{Format: "control_frames", Note: vkeys.Note, Cases: cs}
}

func protoKind(b any) string {
	m := msgWith(0, 0, b)
	fd := m.ProtoReflect().WhichOneof(m.ProtoReflect().Descriptor().Oneofs().ByName("body"))
	return string(fd.Name())
}
