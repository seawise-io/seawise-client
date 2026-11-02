package handshake

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

type vcase struct {
	Name    string         `json:"name"`
	Kind    string         `json:"kind"`
	Input   string         `json:"input,omitempty"`
	Context map[string]any `json:"context,omitempty"`
	Expect  string         `json:"expect"`
	Result  any            `json:"result,omitempty"`
}

type vfile struct {
	Format string       `json:"format"`
	Note   string       `json:"note"`
	Keys   []vkeys.Info `json:"keys"`
	Cases  []vcase      `json:"cases"`
}

type regEntry struct {
	Key      string `json:"key"`
	X        string `json:"x"`
	KID      string `json:"kid"`
	ServerID string `json:"server_id"`
	Status   string `json:"status"`
}

type edgeKey struct {
	EdgeID string `json:"edge_id"`
	X      string `json:"x"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func marshal(m proto.Message) []byte {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

var exporterB = func() [32]byte {
	e := fx.ExporterBytes()
	e[0] ^= 0xff
	return e
}()

func reg(entries ...regEntry) []regEntry { return entries }

func entry(key, server, status string) regEntry {
	return regEntry{Key: key, X: vkeys.B64(vkeys.Pub(key)), KID: vkeys.KID(key), ServerID: server, Status: status}
}

func signedHello(key string, exporter [32]byte, body []byte) []byte {
	return marshal(&pb.Hello{Body: body, Signature: ed25519.Sign(vkeys.Key(key), HelloMessage(exporter, body))})
}

func genHello() vfile {
	var cs []vcase
	ex := fx.ExporterBytes()
	exHex := hex.EncodeToString(ex[:])
	defReg := reg(entry(fx.DeviceA, fx.Server1, StatusActive), entry(fx.DeviceB, fx.Server2, StatusActive))
	hello := func(name string, in []byte, transport string, r []regEntry, expect string, result any) {
		cs = append(cs, vcase{Name: name, Kind: "hello", Input: b64(in), Context: map[string]any{"exporter": exHex, "transport": transport, "registry": r}, Expect: expect, Result: result})
	}
	body := marshal(fx.HelloBody())
	valid := signedHello(fx.DeviceA, ex, body)
	hello("valid", valid, "TRANSPORT_TLS", defReg, "ok", map[string]string{"signed_message": hex.EncodeToString(HelloMessage(ex, body))})
	wsBody := fx.HelloBody()
	wsBody.Transport = pb.Transport_TRANSPORT_WEBSOCKET
	hello("valid-websocket", signedHello(fx.DeviceA, ex, marshal(wsBody)), "TRANSPORT_WEBSOCKET", defReg, "ok", nil)
	hello("transport-mismatch", valid, "TRANSPORT_WEBSOCKET", defReg, "BAD_REQUEST", nil)
	hello("wrong-exporter", signedHello(fx.DeviceA, exporterB, body), "TRANSPORT_TLS", defReg, "INVALID_PROOF", nil)
	hello("signed-by-another-key", signedHello(fx.DeviceB, ex, body), "TRANSPORT_TLS", defReg, "INVALID_PROOF", nil)
	hello("key-not-in-registry", valid, "TRANSPORT_TLS", reg(entry(fx.DeviceB, fx.Server2, StatusActive)), "INVALID_PROOF", nil)
	hello("server-mismatch", valid, "TRANSPORT_TLS", reg(entry(fx.DeviceA, fx.Server2, StatusActive)), "INVALID_PROOF", nil)
	for _, st := range []string{StatusRevoked, StatusCompromised} {
		hello("status-"+st, valid, "TRANSPORT_TLS", reg(entry(fx.DeviceA, fx.Server1, st)), "KEY_REVOKED", nil)
	}
	for _, st := range []string{StatusPending, StatusEnrolPending} {
		hello("status-"+st, valid, "TRANSPORT_TLS", reg(entry(fx.DeviceA, fx.Server1, st)), "NOT_ENROLLED", nil)
	}
	hello("status-unknown", valid, "TRANSPORT_TLS", reg(entry(fx.DeviceA, fx.Server1, "deleted")), "INVALID_PROOF", nil)
	revokedBadSig := signedHello(fx.DeviceB, ex, body)
	hello("revoked-with-bad-signature", revokedBadSig, "TRANSPORT_TLS", reg(entry(fx.DeviceA, fx.Server1, StatusRevoked)), "INVALID_PROOF", nil)
	small := entry(fx.DeviceA, fx.Server1, StatusActive)
	small.X = vkeys.B64(append([]byte{1}, make([]byte, 31)...))
	hello("registry-key-small-order", valid, "TRANSPORT_TLS", reg(small), "INVALID_PROOF", nil)
	other := entry(fx.DeviceA, fx.Server1, StatusActive)
	other.X = vkeys.B64(vkeys.Pub(fx.DeviceB))
	hello("registry-key-thumbprint-mismatch", valid, "TRANSPORT_TLS", reg(other), "INVALID_PROOF", nil)
	sig := ed25519.Sign(vkeys.Key(fx.DeviceA), HelloMessage(ex, body))
	hello("signature-63", marshal(&pb.Hello{Body: body, Signature: sig[:63]}), "TRANSPORT_TLS", defReg, "BAD_REQUEST", nil)
	hello("signature-missing", marshal(&pb.Hello{Body: body}), "TRANSPORT_TLS", defReg, "BAD_REQUEST", nil)
	hiS := append([]byte(nil), sig...)
	hiS[63] |= 0xe0
	hello("signature-non-canonical-s", marshal(&pb.Hello{Body: body, Signature: hiS}), "TRANSPORT_TLS", defReg, "INVALID_PROOF", nil)
	hello("truncated-body", signedHello(fx.DeviceA, ex, body[:len(body)-3]), "TRANSPORT_TLS", defReg, "BAD_REQUEST", nil)
	hello("empty-body", signedHello(fx.DeviceA, ex, nil), "TRANSPORT_TLS", defReg, "BAD_REQUEST", nil)
	unk := append(append([]byte{}, body...), protowire.AppendVarint(protowire.AppendTag(nil, 11, protowire.VarintType), 1)...)
	hello("unknown-field", signedHello(fx.DeviceA, ex, unk), "TRANSPORT_TLS", defReg, "BAD_REQUEST", nil)
	mut := func(name string, f func(*pb.HelloBody), expect string) {
		h := fx.HelloBody()
		f(h)
		hello(name, signedHello(fx.DeviceA, ex, marshal(h)), "TRANSPORT_TLS", defReg, expect, nil)
	}
	mut("capabilities-unsorted", func(h *pb.HelloBody) { h.Capabilities = []string{"zeta", "alpha"} }, "BAD_REQUEST")
	mut("capabilities-duplicate", func(h *pb.HelloBody) { h.Capabilities = []string{"alpha", "alpha"} }, "BAD_REQUEST")
	mut("capabilities-32", func(h *pb.HelloBody) { h.Capabilities = capList(32) }, "ok")
	mut("capabilities-33", func(h *pb.HelloBody) { h.Capabilities = capList(33) }, "BAD_REQUEST")
	mut("capability-32-chars", func(h *pb.HelloBody) { h.Capabilities = []string{fx.Repeat("a", 32)} }, "ok")
	mut("capability-33-chars", func(h *pb.HelloBody) { h.Capabilities = []string{fx.Repeat("a", 33)} }, "BAD_REQUEST")
	mut("capability-bad-charset", func(h *pb.HelloBody) { h.Capabilities = []string{"Raw"} }, "BAD_REQUEST")
	mut("server-id-15", func(h *pb.HelloBody) { h.ServerId = h.ServerId[:15] }, "BAD_REQUEST")
	mut("server-id-17", func(h *pb.HelloBody) { h.ServerId = append(h.ServerId, 0) }, "BAD_REQUEST")
	mut("key-id-42", func(h *pb.HelloBody) { h.KeyId = h.KeyId[:42] }, "BAD_REQUEST")
	mut("key-id-44", func(h *pb.HelloBody) { h.KeyId += "A" }, "BAD_REQUEST")
	mut("run-id-15", func(h *pb.HelloBody) { h.RunId = h.RunId[:15] }, "BAD_REQUEST")
	mut("run-id-17", func(h *pb.HelloBody) { h.RunId = append(h.RunId, 0) }, "BAD_REQUEST")
	mut("agent-version-32", func(h *pb.HelloBody) { h.AgentVersion = "2.1.0-" + fx.Repeat("a", 26) }, "ok")
	mut("agent-version-33", func(h *pb.HelloBody) { h.AgentVersion = "2.1.0-" + fx.Repeat("a", 27) }, "BAD_REQUEST")
	mut("agent-version-build-metadata", func(h *pb.HelloBody) { h.AgentVersion = "2.1.0+abc" }, "BAD_REQUEST")
	mut("agent-version-missing", func(h *pb.HelloBody) { h.AgentVersion = "" }, "BAD_REQUEST")
	mut("transport-unspecified", func(h *pb.HelloBody) { h.Transport = 0 }, "BAD_REQUEST")
	mut("time-nonce-15", func(h *pb.HelloBody) { h.TimeNonce = h.TimeNonce[:15] }, "BAD_REQUEST")
	mut("time-nonce-17", func(h *pb.HelloBody) { h.TimeNonce = append(h.TimeNonce, 0) }, "BAD_REQUEST")
	mut("routes-held-1000", func(h *pb.HelloBody) { h.RoutesHeld = 1000 }, "ok")
	mut("routes-held-1001", func(h *pb.HelloBody) { h.RoutesHeld = 1001 }, "BAD_REQUEST")
	mut("max-streams-0", func(h *pb.HelloBody) { h.MaxStreams = 0 }, "BAD_REQUEST")
	mut("max-streams-4096", func(h *pb.HelloBody) { h.MaxStreams = 4096 }, "ok")
	mut("max-streams-4097", func(h *pb.HelloBody) { h.MaxStreams = 4097 }, "BAD_REQUEST")
	big := fx.HelloBody()
	big.Capabilities = capList(32)
	for i := range big.Capabilities {
		big.Capabilities[i] = fx.Repeat(big.Capabilities[i], 32)
	}
	hello("body-4096-cap", signedHello(fx.DeviceA, ex, fx.Pad(marshal(big), 0, 4097)), "TRANSPORT_TLS", defReg, "BAD_REQUEST", nil)

	// HelloAck, agent side.
	ack := func(name string, a *pb.HelloAck, exporter [32]byte, sentBody []byte, required []string, keys []edgeKey, expect string, result any) {
		cs = append(cs, vcase{Name: name, Kind: "hello_ack", Input: b64(marshal(a)), Context: map[string]any{
			"exporter": hex.EncodeToString(exporter[:]), "sent_body": b64(sentBody), "required": required, "edge_keys": keys,
		}, Expect: expect, Result: result})
	}
	keys := []edgeKey{{fx.EdgeA, vkeys.B64(vkeys.Pub(fx.EdgeA))}, {fx.EdgeB, vkeys.B64(vkeys.Pub(fx.EdgeB))}}
	signAck := func(key string, exporter [32]byte, b *pb.HelloAckBody) *pb.HelloAck {
		raw := marshal(b)
		return &pb.HelloAck{Body: raw, Signature: ed25519.Sign(vkeys.Key(key), AckMessage(exporter, raw))}
	}
	good := fx.HelloAckBody(body)
	ackRes := func(b *pb.HelloAckBody, ms map[string]int64) map[string]any {
		raw := marshal(b)
		return map[string]any{"signed_message": hex.EncodeToString(AckMessage(ex, raw)), "ping_interval_ms": ms["i"], "ping_timeout_ms": ms["t"], "max_streams": b.MaxStreams, "edge_id": b.EdgeId}
	}
	ack("valid", signAck(fx.EdgeA, ex, good), ex, body, []string{}, keys, "ok", ackRes(good, map[string]int64{"i": 20000, "t": 15000}))
	ack("signed-by-non-key-set-key", signAck("edge-rogue", ex, good), ex, body, []string{}, keys, "bad_signature", nil)
	ack("signed-by-other-edge-key", signAck(fx.EdgeB, ex, good), ex, body, []string{}, keys, "bad_signature", nil)
	ack("over-another-exporter", signAck(fx.EdgeA, exporterB, good), ex, body, []string{}, keys, "bad_signature", nil)
	unknownEdge := proto.Clone(good).(*pb.HelloAckBody)
	unknownEdge.EdgeId = "edge-eu-west-1"
	ack("edge-not-in-key-set", signAck(fx.EdgeA, ex, unknownEdge), ex, body, []string{}, keys, "unknown_edge", nil)
	otherBody := fx.HelloBody()
	otherBody.RoutesHeld = 3
	ack("digest-mismatch", signAck(fx.EdgeA, ex, fx.HelloAckBody(marshal(otherBody))), ex, body, []string{}, keys, "digest_mismatch", nil)
	mutAck := func(name string, f func(*pb.HelloAckBody), expect string, ms map[string]int64) {
		b := proto.Clone(good).(*pb.HelloAckBody)
		f(b)
		var res any
		if expect == "ok" {
			res = ackRes(b, ms)
		}
		ack(name, signAck(fx.EdgeA, ex, b), ex, body, []string{}, keys, expect, res)
	}
	mutAck("ping-clamped-low", func(b *pb.HelloAckBody) { b.PingIntervalMs, b.PingTimeoutMs = 1000, 0 }, "ok", map[string]int64{"i": 10000, "t": 15000})
	mutAck("ping-clamped-high", func(b *pb.HelloAckBody) { b.PingIntervalMs, b.PingTimeoutMs = 600000, 600000 }, "ok", map[string]int64{"i": 60000, "t": 30000})
	mutAck("max-streams-above-offer", func(b *pb.HelloAckBody) { b.MaxStreams = 129 }, "bad_negotiation", nil)
	mutAck("max-streams-below-offer", func(b *pb.HelloAckBody) { b.MaxStreams = 64 }, "ok", map[string]int64{"i": 20000, "t": 15000})
	mutAck("minor-above-offer", func(b *pb.HelloAckBody) { b.ProtocolMinor = 1 }, "bad_negotiation", nil)
	mutAck("capability-not-offered", func(b *pb.HelloAckBody) { b.Capabilities = []string{"raw_tcp"} }, "bad_negotiation", nil)
	mutAck("max-control-bytes-32768", func(b *pb.HelloAckBody) { b.MaxControlBytes = 32768 }, "bad_ack", nil)
	mutAck("session-age-43199", func(b *pb.HelloAckBody) { b.MaxSessionAgeS = 43199 }, "bad_ack", nil)
	mutAck("session-age-86401", func(b *pb.HelloAckBody) { b.MaxSessionAgeS = 86401 }, "bad_ack", nil)
	mutAck("edge-id-bad", func(b *pb.HelloAckBody) { b.EdgeId = "edge-1" }, "bad_ack", nil)
	mutAck("session-id-15", func(b *pb.HelloAckBody) { b.SessionId = b.SessionId[:15] }, "bad_ack", nil)
	ack("required-capability-missing", signAck(fx.EdgeA, ex, good), ex, body, []string{"datagram"}, keys, "edge_too_old", nil)
	ack("signature-missing", &pb.HelloAck{Body: marshal(good)}, ex, body, []string{}, keys, "bad_ack", nil)

	// Supersede decision at the edge.
	sup := func(name string, oldRun, newRun []byte, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "supersede", Context: map[string]any{"old_run_id": hex.EncodeToString(oldRun), "new_run_id": hex.EncodeToString(newRun)}, Expect: expect})
	}
	sup("same-run-reconnect", fx.Bytes("run-1", 16), fx.Bytes("run-1", 16), "no_message")
	sup("different-run", fx.Bytes("run-1", 16), fx.Bytes("run-2", 16), "drain_superseded_stop")

	return vfile{Format: "hello", Note: vkeys.Note, Keys: vkeys.Infos(fx.DeviceA, fx.DeviceB, fx.EdgeA, fx.EdgeB, "edge-rogue"), Cases: cs}
}

func capList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "cap" + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	return out
}

func genNegotiation() vfile {
	var cs []vcase
	neg := func(name string, am uint32, ac []string, em uint32, ec []string, minor uint32, caps []string) {
		cs = append(cs, vcase{Name: name, Kind: "negotiate", Context: map[string]any{"agent_minor": am, "agent_capabilities": ac, "edge_minor": em, "edge_capabilities": ec}, Expect: "ok", Result: map[string]any{"protocol_minor": minor, "capabilities": caps}})
	}
	e := []string{}
	neg("launch", 0, e, 0, e, 0, e)
	neg("agent-newer-minor", 3, e, 1, e, 1, e)
	neg("edge-newer-minor", 1, e, 4, e, 1, e)
	neg("intersection", 0, []string{"datagram", "raw_tcp"}, 0, []string{"quic", "raw_tcp"}, 0, []string{"raw_tcp"})
	neg("unknown-strings-ignored", 0, []string{"future_thing", "raw_tcp"}, 0, []string{"raw_tcp", "zzz"}, 0, []string{"raw_tcp"})
	neg("disjoint", 0, []string{"a"}, 0, []string{"b"}, 0, e)
	neg("edge-unsorted-input", 0, []string{"a", "b", "c"}, 0, []string{"c", "a"}, 0, []string{"a", "c"})

	ex := fx.ExporterBytes()
	h := fx.HelloBody()
	h.Capabilities = []string{"datagram", "raw_tcp"}
	body := marshal(h)
	d := sha256.Sum256(body)
	ackFor := func(caps []string, digest []byte) *pb.HelloAck {
		b := fx.HelloAckBody(body)
		b.Capabilities, b.OfferedDigest = caps, digest
		raw := marshal(b)
		return &pb.HelloAck{Body: raw, Signature: ed25519.Sign(vkeys.Key(fx.EdgeA), AckMessage(ex, raw))}
	}
	keys := []edgeKey{{fx.EdgeA, vkeys.B64(vkeys.Pub(fx.EdgeA))}}
	ack := func(name string, a *pb.HelloAck, required []string, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "hello_ack", Input: b64(marshal(a)), Context: map[string]any{
			"exporter": hex.EncodeToString(ex[:]), "sent_body": b64(body), "required": required, "edge_keys": keys,
		}, Expect: expect})
	}
	ack("ack-intersection", ackFor([]string{"raw_tcp"}, d[:]), []string{}, "ok")
	ack("ack-required-present", ackFor([]string{"raw_tcp"}, d[:]), []string{"raw_tcp"}, "ok")
	ack("ack-required-missing", ackFor([]string{"raw_tcp"}, d[:]), []string{"datagram"}, "edge_too_old")
	ack("ack-required-dropped-by-downgrade", ackFor([]string{}, d[:]), []string{"raw_tcp"}, "edge_too_old")
	ack("ack-capability-added", ackFor([]string{"quic"}, d[:]), []string{}, "bad_negotiation")
	ack("ack-unsorted", ackFor([]string{"raw_tcp", "datagram"}, d[:]), []string{}, "bad_ack")
	bad := d
	bad[0] ^= 1
	ack("offered-digest-mismatch", ackFor([]string{"raw_tcp"}, bad[:]), []string{}, "digest_mismatch")
	return vfile{Format: "negotiation", Note: vkeys.Note, Keys: vkeys.Infos(fx.EdgeA), Cases: cs}
}

type peerTranscript struct {
	DialerHello   string `json:"dialer_hello"`
	AcceptorHello string `json:"acceptor_hello"`
	DialerSig     string `json:"dialer_sig"`
	AcceptorSig   string `json:"acceptor_sig"`
}

func nonce(label string) [NonceSize]byte {
	var n [NonceSize]byte
	copy(n[:], fx.Bytes(label, NonceSize))
	return n
}

func genRelay() vfile {
	var cs []vcase
	keys := []edgeKey{{fx.EdgeA, vkeys.B64(vkeys.Pub(fx.EdgeA))}, {fx.EdgeB, vkeys.B64(vkeys.Pub(fx.EdgeB))}}
	d := PeerHello{EdgeID: fx.EdgeA, Nonce: nonce("dialer-nonce")}
	a := PeerHello{EdgeID: fx.EdgeB, Nonce: nonce("acceptor-nonce")}
	enc := func(h PeerHello) string {
		b, err := AppendPeerHello(nil, h)
		if err != nil {
			panic(err)
		}
		return b64(b)
	}
	tr := func(name string, dh, ah PeerHello, dsig, asig []byte, expectAcceptor, expectDialer string, result any) {
		dialed := ah.EdgeID
		if name == "acceptor-not-dialed" || name == "peer-claims-own-id" {
			dialed = fx.EdgeB
		}
		cs = append(cs, vcase{Name: name, Kind: "peer", Context: map[string]any{
			"transcript":     peerTranscript{enc(dh), enc(ah), b64(dsig), b64(asig)},
			"dialed":         dialed,
			"edge_keys":      keys,
			"acceptor_check": expectAcceptor,
		}, Expect: expectDialer, Result: result})
	}
	dsig := SignPeer(vkeys.Key(fx.EdgeA), d, a, RoleDialer)
	asig := SignPeer(vkeys.Key(fx.EdgeB), d, a, RoleAcceptor)
	tr("good", d, a, dsig, asig, "ok", "ok", map[string]string{
		"dialer_message":   hex.EncodeToString(PeerMessage(d, a, RoleDialer)),
		"acceptor_message": hex.EncodeToString(PeerMessage(d, a, RoleAcceptor)),
	})
	tr("wrong-key", d, a, SignPeer(vkeys.Key("edge-rogue"), d, a, RoleDialer), SignPeer(vkeys.Key("edge-rogue"), d, a, RoleAcceptor), "bad_signature", "bad_signature", nil)
	tr("swapped-roles", d, a, SignPeer(vkeys.Key(fx.EdgeA), d, a, RoleAcceptor), SignPeer(vkeys.Key(fx.EdgeB), d, a, RoleDialer), "bad_signature", "bad_signature", nil)
	old := PeerHello{EdgeID: fx.EdgeB, Nonce: nonce("old-acceptor-nonce")}
	tr("replayed-nonce", d, a, SignPeer(vkeys.Key(fx.EdgeA), d, old, RoleDialer), SignPeer(vkeys.Key(fx.EdgeB), d, old, RoleAcceptor), "bad_signature", "bad_signature", nil)
	refl := PeerHello{EdgeID: fx.EdgeB, Nonce: d.Nonce}
	tr("reflected-nonce", d, refl, SignPeer(vkeys.Key(fx.EdgeA), d, refl, RoleDialer), SignPeer(vkeys.Key(fx.EdgeB), d, refl, RoleAcceptor), "reflected_nonce", "reflected_nonce", nil)
	hi := PeerHello{EdgeID: fx.EdgeB, Nonce: d.Nonce}
	lo := PeerHello{EdgeID: fx.EdgeA, Nonce: a.Nonce}
	tr("higher-ordinal-dials", hi, lo, SignPeer(vkeys.Key(fx.EdgeB), hi, lo, RoleDialer), SignPeer(vkeys.Key(fx.EdgeA), hi, lo, RoleAcceptor), "dial_order", "dial_order", nil)
	self := PeerHello{EdgeID: fx.EdgeA, Nonce: a.Nonce}
	tr("peer-claims-own-id", d, self, dsig, SignPeer(vkeys.Key(fx.EdgeA), d, self, RoleAcceptor), "wrong_peer", "wrong_peer", nil)
	c := PeerHello{EdgeID: "edge-us-east-3", Nonce: a.Nonce}
	tr("acceptor-not-dialed", d, c, SignPeer(vkeys.Key(fx.EdgeA), d, c, RoleDialer), SignPeer(vkeys.Key("edge-us-east-3"), d, c, RoleAcceptor), "ok", "wrong_peer", nil)

	ph := func(name string, in []byte, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "peer_hello", Input: b64(in), Expect: expect})
	}
	good, _ := AppendPeerHello(nil, d)
	ph("peer-hello-valid", good, "ok")
	ph("peer-hello-truncated", good[:len(good)-1], "malformed")
	ph("peer-hello-zero-length", append([]byte{0}, d.Nonce[:]...), "malformed")
	ph("peer-hello-64-length", append([]byte{64}, make([]byte, 96)...), "malformed")
	ph("peer-hello-bad-id", append(append([]byte{6}, "edge-1"...), d.Nonce[:]...), "malformed")

	rp := func(name string, p *pb.RelayPrefix, peer, expect string) {
		raw := marshal(p)
		cs = append(cs, vcase{Name: name, Kind: "relay_prefix", Input: b64(append([]byte{byte(len(raw) >> 8), byte(len(raw))}, raw...)), Context: map[string]any{"peer": peer}, Expect: expect})
	}
	base := func() *pb.RelayPrefix {
		return &pb.RelayPrefix{Version: 1, ServerId: fx.UUID(fx.Server1), ExpectedEpoch: 7, IngressEdgeId: fx.EdgeA, Hop: 1}
	}
	rp("prefix-valid", base(), fx.EdgeA, "ok")
	p := base()
	p.Hop = 2
	rp("prefix-hop-2", p, fx.EdgeA, string(wire.CodeBadValue))
	rp("prefix-wrong-ingress", base(), fx.EdgeB, string(wire.CodeWrongPeer))
	p = base()
	p.Version = 2
	rp("prefix-version-2", p, fx.EdgeA, string(wire.CodeBadValue))
	p = base()
	p.ExpectedEpoch = 0
	rp("prefix-epoch-0", p, fx.EdgeA, string(wire.CodeBadValue))
	return vfile{Format: "relay", Note: vkeys.Note, Keys: vkeys.Infos(fx.EdgeA, fx.EdgeB, "edge-us-east-3", "edge-rogue"), Cases: cs}
}
