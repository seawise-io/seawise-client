package wire

import (
	"encoding/binary"
	"encoding/hex"

	"google.golang.org/protobuf/encoding/protowire"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func frame16(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

// headerResult is the decoded header as vectors show it.
type headerResult struct {
	Version      uint32 `json:"version"`
	Type         string `json:"type"`
	AppID        string `json:"app_id"`
	VisitorToken int    `json:"visitor_token_len"`
	ClientIP     string `json:"client_ip"`
	Scheme       string `json:"scheme"`
	ALPN         string `json:"alpn"`
	EdgeTimeMs   int64  `json:"edge_time_ms"`
	TraceID      string `json:"trace_id"`
	StaleOk      int    `json:"stale_ok_until_len"`
}

func headerResultOf(h *pb.StreamHeader) headerResult {
	return headerResult{
		Version: h.Version, Type: h.Type.String(), AppID: fx.UUIDString(h.AppId),
		VisitorToken: len(h.VisitorToken), ClientIP: hex.EncodeToString(h.ClientIp),
		Scheme: h.Scheme.String(), ALPN: h.Alpn, EdgeTimeMs: h.EdgeTimeMs,
		TraceID: hex.EncodeToString(h.TraceId), StaleOk: len(h.StaleOkUntil),
	}
}

func genStreamHeader() vfile {
	var cs []vcase
	add := func(name string, input []byte, ctx map[string]any, expect string, result any) {
		cs = append(cs, vcase{Name: name, Input: b64(input), Context: ctx, Expect: expect, Result: result})
	}
	hdr := func(name string, f func(*pb.StreamHeader), caps []string, expect string) {
		h := fx.StreamHeader()
		f(h)
		in := frame16(mustMarshal(h))
		ctx := map[string]any{"kind": "header", "layer": "message", "capabilities": caps}
		if expect != "ok" {
			add(name, in, ctx, expect, nil)
			return
		}
		got, err := DecodeStreamHeader(mustMarshal(h), caps)
		if err != nil {
			panic(name + ": " + err.Error())
		}
		add(name, in, ctx, "ok", headerResultOf(got))
	}
	none := []string{}
	hdr("valid", func(*pb.StreamHeader) {}, none, "ok")
	hdr("valid-public-route-no-token", func(h *pb.StreamHeader) { h.VisitorToken = "" }, none, "ok")
	hdr("valid-http11-ipv6", func(h *pb.StreamHeader) {
		h.Alpn = "http/1.1"
		h.ClientIp = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	}, none, "ok")
	hdr("ipv4-mapped-normalised", func(h *pb.StreamHeader) {
		h.ClientIp = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 9}
	}, none, "ok")
	hdr("ipv4-compatible-not-normalised", func(h *pb.StreamHeader) {
		h.ClientIp = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 198, 51, 100, 9}
	}, none, "ok")
	hdr("client-ip-5", func(h *pb.StreamHeader) { h.ClientIp = []byte{1, 2, 3, 4, 5} }, none, "bad_value")
	hdr("client-ip-missing", func(h *pb.StreamHeader) { h.ClientIp = nil }, none, "bad_value")
	hdr("client-ip-17", func(h *pb.StreamHeader) { h.ClientIp = fx.Bytes("ip", 17) }, none, "too_large")
	hdr("app-id-15", func(h *pb.StreamHeader) { h.AppId = h.AppId[:15] }, none, "bad_value")
	hdr("app-id-17", func(h *pb.StreamHeader) { h.AppId = fx.Bytes("app", 17) }, none, "too_large")
	hdr("visitor-token-2048", func(h *pb.StreamHeader) { h.VisitorToken = fx.JWS(2048) }, none, "ok")
	hdr("visitor-token-2049", func(h *pb.StreamHeader) { h.VisitorToken = fx.JWS(2049) }, none, "too_large")
	hdr("visitor-token-not-jws", func(h *pb.StreamHeader) { h.VisitorToken = "Bearer abc" }, none, "bad_value")
	hdr("stale-ok-512", func(h *pb.StreamHeader) { h.StaleOkUntil = fx.JWS(512) }, none, "ok")
	hdr("stale-ok-513", func(h *pb.StreamHeader) { h.StaleOkUntil = fx.JWS(513) }, none, "too_large")
	hdr("stale-ok-without-token", func(h *pb.StreamHeader) { h.VisitorToken, h.StaleOkUntil = "", fx.JWS(200) }, none, "bad_value")
	hdr("version-0", func(h *pb.StreamHeader) { h.Version = 0 }, none, "bad_value")
	hdr("version-2", func(h *pb.StreamHeader) { h.Version = 2 }, none, "bad_value")
	hdr("type-unspecified", func(h *pb.StreamHeader) { h.Type = 0 }, none, "bad_value")
	hdr("raw-tcp-without-capability", func(h *pb.StreamHeader) { h.Type = pb.StreamType_RAW_TCP }, none, "not_negotiated")
	hdr("raw-tcp-with-capability", func(h *pb.StreamHeader) { h.Type = pb.StreamType_RAW_TCP }, []string{"raw_tcp"}, "ok")
	hdr("scheme-unspecified", func(h *pb.StreamHeader) { h.Scheme = 0 }, none, "bad_value")
	hdr("alpn-h3", func(h *pb.StreamHeader) { h.Alpn = "h3" }, none, "bad_value")
	hdr("alpn-missing", func(h *pb.StreamHeader) { h.Alpn = "" }, none, "bad_value")
	hdr("alpn-17", func(h *pb.StreamHeader) { h.Alpn = fx.Repeat("h", 17) }, none, "too_large")
	hdr("trace-id-zero", func(h *pb.StreamHeader) { h.TraceId = make([]byte, 16) }, none, "bad_value")
	hdr("trace-id-15", func(h *pb.StreamHeader) { h.TraceId = h.TraceId[:15] }, none, "bad_value")
	hdr("trace-id-missing", func(h *pb.StreamHeader) { h.TraceId = nil }, none, "bad_value")
	hdr("edge-time-negative", func(h *pb.StreamHeader) { h.EdgeTimeMs = -1 }, none, "bad_value")

	valid := mustMarshal(fx.StreamHeader())
	ctx := func(layer string) map[string]any {
		return map[string]any{"kind": "header", "layer": layer, "capabilities": []string{}}
	}
	add("unknown-field-11", frame16(append(append([]byte{}, valid...), protowire.AppendVarint(protowire.AppendTag(nil, 11, protowire.VarintType), 1)...)), ctx("message"), "unknown_field", nil)
	add("duplicate-app-id", frame16(append(append([]byte{}, valid...), protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), fx.UUID(fx.App2))...)), ctx("message"), "duplicate_field", nil)
	add("header-length-0", []byte{0, 0}, ctx("frame"), "empty", nil)
	add("header-length-4096", frame16(fx.Bytes("h", 4096)), ctx("frame"), "ok", nil)
	add("header-length-4097", []byte{0x10, 0x01}, ctx("frame"), "too_large", nil)
	add("header-truncated", frame16(valid)[:20], ctx("frame"), "truncated", nil)

	rctx := map[string]any{"kind": "reply", "layer": "message"}
	for c := pb.ReplyCode_ACCEPTED; c <= pb.ReplyCode_BAD_HEADER; c++ {
		add("reply-"+c.String(), frame16(mustMarshal(&pb.StreamReply{Code: c})), rctx, "ok", c.String())
	}
	add("reply-unspecified", frame16([]byte{0x08, 0x00}), rctx, "bad_value", nil)
	add("reply-empty-message", []byte{0x00, 0x00}, rctx, "empty", nil)
	add("reply-unknown-code", frame16([]byte{0x08, 0x07}), rctx, "bad_value", nil)
	add("reply-unknown-field", frame16([]byte{0x08, 0x01, 0x10, 0x01}), rctx, "unknown_field", nil)
	add("reply-length-65", []byte{0x00, 0x41}, rctx, "too_large", nil)
	return vfile{Format: "stream_header", Note: vkeys.Note, Cases: cs}
}
