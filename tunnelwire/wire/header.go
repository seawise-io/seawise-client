package wire

import (
	"io"
	"slices"

	"google.golang.org/protobuf/proto"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// CapRawTCP is the capability that admits RAW_TCP streams.
const CapRawTCP = "raw_tcp"

// normaliseIP returns ip with an IPv4-mapped IPv6 address cut to 4 bytes.
func normaliseIP(ip []byte) []byte {
	if len(ip) == 16 && allZero(ip[:10]) && ip[10] == 0xff && ip[11] == 0xff {
		return ip[12:16]
	}
	return ip
}

// DecodeStreamHeader decodes and validates a data-stream header. caps is
// the negotiated capability set. client_ip comes back normalised.
func DecodeStreamHeader(b []byte, caps []string) (*pb.StreamHeader, error) {
	if len(b) == 0 {
		return nil, fail(CodeEmpty, "header")
	}
	if len(b) > MaxHeader {
		return nil, fail(CodeTooLarge, "header")
	}
	h := &pb.StreamHeader{}
	if _, err := decodeStrict(b, h, false); err != nil {
		return nil, err
	}
	h.ClientIp = normaliseIP(h.ClientIp)
	if h.Type == pb.StreamType_RAW_TCP && !slices.Contains(caps, CapRawTCP) {
		return nil, fail(CodeNotNegotiated, "type")
	}
	if err := firstErr(
		check(h.Version == HeaderVersion, "version"),
		check(h.Type != pb.StreamType_STREAM_TYPE_UNSPECIFIED, "type"),
		check(len(h.AppId) == 16, "app_id"),
		check(h.VisitorToken == "" || ValidCompactJWS(h.VisitorToken, MaxVisitorToken), "visitor_token"),
		check(len(h.ClientIp) == 4 || len(h.ClientIp) == 16, "client_ip"),
		check(h.Scheme == pb.Scheme_HTTPS, "scheme"),
		check(h.Alpn == "h2" || h.Alpn == "http/1.1", "alpn"),
		check(h.EdgeTimeMs >= 0, "edge_time_ms"),
		check(len(h.TraceId) == 16 && !allZero(h.TraceId), "trace_id"),
		check(h.StaleOkUntil == "" || ValidCompactJWS(h.StaleOkUntil, MaxStaleOk), "stale_ok_until"),
		check(h.StaleOkUntil == "" || h.VisitorToken != "", "stale_ok_until"),
	); err != nil {
		return nil, err
	}
	return h, nil
}

// EncodeStreamHeader normalises client_ip, validates h and marshals it.
func EncodeStreamHeader(h *pb.StreamHeader, caps []string) ([]byte, error) {
	n := proto.Clone(h).(*pb.StreamHeader)
	n.ClientIp = normaliseIP(n.ClientIp)
	b, err := marshal(n)
	if err != nil {
		return nil, fail(CodeBadValue, "header")
	}
	if _, err := DecodeStreamHeader(b, caps); err != nil {
		return nil, err
	}
	return b, nil
}

// AppendStreamHeader appends the framed header: uint16 length and bytes.
func AppendStreamHeader(dst []byte, h *pb.StreamHeader, caps []string) ([]byte, error) {
	b, err := EncodeStreamHeader(h, caps)
	if err != nil {
		return dst, err
	}
	return appendFrame16(dst, b, MaxHeader, "header")
}

// ReadStreamHeader reads and decodes a framed header.
func ReadStreamHeader(r io.Reader, caps []string) (*pb.StreamHeader, error) {
	b, err := readFrame16(r, MaxHeader, "header")
	if err != nil {
		return nil, err
	}
	return DecodeStreamHeader(b, caps)
}

// DecodeStreamReply decodes and validates a reply.
func DecodeStreamReply(b []byte) (pb.ReplyCode, error) {
	if len(b) == 0 {
		return 0, fail(CodeEmpty, "reply")
	}
	if len(b) > MaxReply {
		return 0, fail(CodeTooLarge, "reply")
	}
	r := &pb.StreamReply{}
	if _, err := decodeStrict(b, r, false); err != nil {
		return 0, err
	}
	if r.Code == pb.ReplyCode_REPLY_UNSPECIFIED {
		return 0, fail(CodeBadValue, "code")
	}
	return r.Code, nil
}

// AppendStreamReply appends the framed reply.
func AppendStreamReply(dst []byte, code pb.ReplyCode) ([]byte, error) {
	b, err := marshal(&pb.StreamReply{Code: code})
	if err != nil {
		return dst, fail(CodeBadValue, "reply")
	}
	if _, err := DecodeStreamReply(b); err != nil {
		return dst, err
	}
	return appendFrame16(dst, b, MaxReply, "reply")
}

// ReadStreamReply reads and decodes a framed reply.
func ReadStreamReply(r io.Reader) (pb.ReplyCode, error) {
	b, err := readFrame16(r, MaxReply, "reply")
	if err != nil {
		return 0, err
	}
	return DecodeStreamReply(b)
}

// DecodeRelayPrefix decodes and validates a relay prefix received from the
// authenticated peer edge peerID.
func DecodeRelayPrefix(b []byte, peerID string) (*pb.RelayPrefix, error) {
	if len(b) == 0 {
		return nil, fail(CodeEmpty, "relay")
	}
	if len(b) > MaxRelayPrefix {
		return nil, fail(CodeTooLarge, "relay")
	}
	p := &pb.RelayPrefix{}
	if _, err := decodeStrict(b, p, false); err != nil {
		return nil, err
	}
	if err := firstErr(
		check(p.Version == RelayVersion, "version"),
		check(len(p.ServerId) == 16, "server_id"),
		check(p.ExpectedEpoch >= 1, "expected_epoch"),
		check(ValidEdgeID(p.IngressEdgeId), "ingress_edge_id"),
		check(p.Hop == RelayHop, "hop"),
	); err != nil {
		return nil, err
	}
	if p.IngressEdgeId != peerID {
		return nil, fail(CodeWrongPeer, "ingress_edge_id")
	}
	return p, nil
}

// AppendRelayPrefix appends the framed prefix: uint16 length and bytes.
func AppendRelayPrefix(dst []byte, p *pb.RelayPrefix) ([]byte, error) {
	b, err := marshal(p)
	if err != nil {
		return dst, fail(CodeBadValue, "relay")
	}
	if _, err := DecodeRelayPrefix(b, p.IngressEdgeId); err != nil {
		return dst, err
	}
	return appendFrame16(dst, b, MaxRelayPrefix, "relay")
}

// ReadRelayPrefix reads and decodes a framed relay prefix.
func ReadRelayPrefix(r io.Reader, peerID string) (*pb.RelayPrefix, error) {
	b, err := readFrame16(r, MaxRelayPrefix, "relay")
	if err != nil {
		return nil, err
	}
	return DecodeRelayPrefix(b, peerID)
}
