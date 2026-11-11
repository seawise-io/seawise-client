// Package fixtures builds valid messages for tests and vectors.
package fixtures

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// Fixed identifiers used across vectors.
const (
	Server1  = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
	Server2  = "7c6b5a49-3827-4615-a4b3-c2d1e0f9a8b7"
	App1     = "0b8d7e3a-6f1c-4d2e-9a5b-8c7d6e5f4a3b"
	App2     = "1c9e8f4b-7a2d-4e3f-8b6c-9d8e7f6a5b4c"
	EdgeA    = "edge-us-east-1"
	EdgeB    = "edge-us-east-2"
	DeviceA  = "device-a"
	DeviceB  = "device-b"
	Version  = "2.1.0"
	Exporter = "c0ffee00c0ffee01c0ffee02c0ffee03c0ffee04c0ffee05c0ffee06c0ffee07"
)

// UUID returns the 16 bytes of a canonical UUID string.
func UUID(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("bad uuid " + s)
	}
	return b
}

// UUIDString formats 16 bytes as a canonical UUID.
func UUIDString(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Bytes returns n bytes derived from label.
func Bytes(label string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		d := sha256.Sum256([]byte(label + string(rune('a'+i))))
		out = append(out, d[:]...)
	}
	return out[:n]
}

// ExporterBytes is the fixed exporter of the vectors.
func ExporterBytes() [32]byte {
	var e [32]byte
	b, _ := hex.DecodeString(Exporter)
	copy(e[:], b)
	return e
}

// HelloBody is a valid HelloBody for DeviceA on Server1.
func HelloBody() *pb.HelloBody {
	return &pb.HelloBody{
		ServerId:      UUID(Server1),
		KeyId:         vkeys.KID(DeviceA),
		RunId:         Bytes("run-1", 16),
		ProtocolMinor: 0,
		AgentVersion:  Version,
		Transport:     pb.Transport_TRANSPORT_TLS,
		TimeNonce:     Bytes("time-nonce-1", 16),
		RoutesHeld:    2,
		MaxStreams:    128,
	}
}

// HelloAckBody is a valid HelloAckBody from EdgeA answering helloBody.
func HelloAckBody(helloBody []byte) *pb.HelloAckBody {
	d := sha256.Sum256(helloBody)
	return &pb.HelloAckBody{
		SessionId:       Bytes("session-1", 16),
		EdgeId:          EdgeA,
		ProtocolMinor:   0,
		OfferedDigest:   d[:],
		PingIntervalMs:  20000,
		PingTimeoutMs:   15000,
		MaxStreams:      128,
		MaxControlBytes: 65536,
		MaxSessionAgeS:  64800,
	}
}

// JWS returns a syntactically valid compact JWS of exactly n bytes.
func JWS(n int) string {
	if n < 5 {
		panic("jws too short")
	}
	s := "eyJh.eyJi." + strings.Repeat("A", max(n-10, 1))
	return s[:n]
}

// StreamHeader is a valid header for App1.
func StreamHeader() *pb.StreamHeader {
	return &pb.StreamHeader{
		Version:      1,
		Type:         pb.StreamType_HTTP,
		AppId:        UUID(App1),
		VisitorToken: JWS(300),
		ClientIp:     []byte{203, 0, 113, 7},
		Scheme:       pb.Scheme_HTTPS,
		Alpn:         "h2",
		EdgeTimeMs:   1793000000123,
		TraceId:      Bytes("trace-1", 16),
	}
}

// Repeat returns s repeated to n bytes.
func Repeat(s string, n int) string { return strings.Repeat(s, n/len(s)+1)[:n] }

// Pad returns b padded with c to n bytes.
func Pad(b []byte, c byte, n int) []byte { return append(b, bytes.Repeat([]byte{c}, n-len(b))...) }
