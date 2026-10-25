package wire

import (
	"math"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fieldCaps is the byte cap of every string and bytes field. A field that
// is missing here is refused, so a schema change cannot add an uncapped
// field silently.
var fieldCaps = map[protoreflect.FullName]int{
	"seawise.tunnel.v1.Hello.body":                   MaxHelloBody,
	"seawise.tunnel.v1.Hello.signature":              SignatureSize,
	"seawise.tunnel.v1.HelloBody.server_id":          16,
	"seawise.tunnel.v1.HelloBody.key_id":             43,
	"seawise.tunnel.v1.HelloBody.run_id":             16,
	"seawise.tunnel.v1.HelloBody.capabilities":       MaxCapabilityLen,
	"seawise.tunnel.v1.HelloBody.agent_version":      MaxAgentVersion,
	"seawise.tunnel.v1.HelloBody.time_nonce":         16,
	"seawise.tunnel.v1.HelloAck.body":                MaxHelloAckBody,
	"seawise.tunnel.v1.HelloAck.signature":           SignatureSize,
	"seawise.tunnel.v1.HelloAckBody.session_id":      16,
	"seawise.tunnel.v1.HelloAckBody.edge_id":         MaxEdgeID,
	"seawise.tunnel.v1.HelloAckBody.capabilities":    MaxCapabilityLen,
	"seawise.tunnel.v1.HelloAckBody.offered_digest":  32,
	"seawise.tunnel.v1.HelloRefuse.detail":           MaxDetail,
	"seawise.tunnel.v1.RouteSet.jws":                 MaxRouteSetJWS,
	"seawise.tunnel.v1.RouteSet.signed_time":         MaxSignedTime,
	"seawise.tunnel.v1.Revoke.app_id":                16,
	"seawise.tunnel.v1.Revoke.detail":                MaxDetail,
	"seawise.tunnel.v1.MinVersion.min_agent_version": MaxAgentVersion,
	"seawise.tunnel.v1.PolicyVersion.flags":          MaxFlags,
	"seawise.tunnel.v1.DeviceCall.idempotency_key":   16,
	"seawise.tunnel.v1.DeviceCall.path_suffix":       MaxPathSuffix,
	"seawise.tunnel.v1.DeviceCall.dpop":              MaxDPoP,
	"seawise.tunnel.v1.DeviceCall.body":              MaxDeviceBody,
	"seawise.tunnel.v1.DeviceResult.body":            MaxDeviceBody,
	"seawise.tunnel.v1.DeviceResult.dpop_nonce":      MaxDPoPNonce,
	"seawise.tunnel.v1.Error.detail":                 MaxDetail,
	"seawise.tunnel.v1.StreamHeader.app_id":          16,
	"seawise.tunnel.v1.StreamHeader.visitor_token":   MaxVisitorToken,
	"seawise.tunnel.v1.StreamHeader.client_ip":       16,
	"seawise.tunnel.v1.StreamHeader.alpn":            16,
	"seawise.tunnel.v1.StreamHeader.trace_id":        16,
	"seawise.tunnel.v1.StreamHeader.stale_ok_until":  MaxStaleOk,
	"seawise.tunnel.v1.RelayPrefix.server_id":        16,
	"seawise.tunnel.v1.RelayPrefix.ingress_edge_id":  MaxEdgeID,
}

// countCaps is the entry cap of every repeated field.
var countCaps = map[protoreflect.FullName]int{
	"seawise.tunnel.v1.HelloBody.capabilities":    MaxCapabilities,
	"seawise.tunnel.v1.HelloAckBody.capabilities": MaxCapabilities,
}

// scan checks b against the strict rules for md without allocating. top
// marks ControlMessage, whose field numbers 24-99 are capability kinds.
// It reports whether b carries a capability kind.
func scan(b []byte, md protoreflect.MessageDescriptor, top bool) (capKind bool, err error) {
	var seen [32]int
	oneofSet := false
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false, fail(CodeMalformed, string(md.Name()))
		}
		if n != protowire.SizeTag(num) {
			return false, fail(CodeMalformed, string(md.Name()))
		}
		b = b[n:]
		fd := md.Fields().ByNumber(num)
		if fd == nil {
			if top && num >= firstCapabilityField && num <= lastCapabilityField {
				m := protowire.ConsumeFieldValue(num, typ, b)
				if m < 0 {
					return false, fail(CodeMalformed, string(md.Name()))
				}
				b = b[m:]
				if oneofSet {
					return false, fail(CodeMultipleBodies, string(md.Name()))
				}
				oneofSet, capKind = true, true
				continue
			}
			return false, fail(CodeUnknownField, string(md.Name()))
		}
		name := string(fd.FullName())
		if int(num) >= len(seen) {
			return false, fail(CodeUnknownField, name)
		}
		seen[num]++
		if fd.Cardinality() == protoreflect.Repeated {
			if seen[num] > countCaps[fd.FullName()] {
				return false, fail(CodeTooLarge, name)
			}
		} else if seen[num] > 1 {
			return false, fail(CodeDuplicateField, name)
		}
		if fd.ContainingOneof() != nil {
			if oneofSet {
				return false, fail(CodeMultipleBodies, name)
			}
			oneofSet = true
		}
		switch fd.Kind() {
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Int64Kind, protoreflect.EnumKind:
			if typ != protowire.VarintType {
				return false, fail(CodeWireType, name)
			}
			v, m := protowire.ConsumeVarint(b)
			if m < 0 || m != protowire.SizeVarint(v) {
				return false, fail(CodeMalformed, name)
			}
			b = b[m:]
			if err := checkVarint(fd, v); err != nil {
				return false, err
			}
		case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
			if typ != protowire.BytesType {
				return false, fail(CodeWireType, name)
			}
			l, m := protowire.ConsumeVarint(b)
			if m < 0 || m != protowire.SizeVarint(l) {
				return false, fail(CodeMalformed, name)
			}
			b = b[m:]
			if l > uint64(len(b)) {
				return false, fail(CodeMalformed, name)
			}
			v := b[:l]
			b = b[l:]
			if fd.Kind() == protoreflect.MessageKind {
				if _, err := scan(v, fd.Message(), false); err != nil {
					return false, err
				}
				continue
			}
			limit, ok := fieldCaps[fd.FullName()]
			if !ok {
				return false, fail(CodeUnknownField, name)
			}
			if len(v) > limit {
				return false, fail(CodeTooLarge, name)
			}
		default:
			return false, fail(CodeUnknownField, name)
		}
	}
	return capKind, nil
}

func checkVarint(fd protoreflect.FieldDescriptor, v uint64) error {
	name := string(fd.FullName())
	switch fd.Kind() {
	case protoreflect.Uint32Kind:
		if v > math.MaxUint32 {
			return fail(CodeBadValue, name)
		}
	case protoreflect.EnumKind:
		s := int64(v)
		if s < math.MinInt32 || s > math.MaxInt32 {
			return fail(CodeBadValue, name)
		}
		if fd.Enum().Values().ByNumber(protoreflect.EnumNumber(s)) == nil {
			return fail(CodeBadValue, name)
		}
	}
	return nil
}

// decodeStrict scans b and then unmarshals it into m.
func decodeStrict(b []byte, m proto.Message, top bool) (capKind bool, err error) {
	capKind, err = scan(b, m.ProtoReflect().Descriptor(), top)
	if err != nil {
		return false, err
	}
	if err := (proto.UnmarshalOptions{}).Unmarshal(b, m); err != nil {
		return false, fail(CodeBadValue, string(m.ProtoReflect().Descriptor().Name()))
	}
	return capKind, nil
}

func marshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}
