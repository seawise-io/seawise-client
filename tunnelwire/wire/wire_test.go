package wire

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func wantCode(t *testing.T, err error, want Code) {
	t.Helper()
	if CodeOf(err) != want {
		t.Fatalf("got %v, want %s", err, want)
	}
}

func TestEveryFieldCapped(t *testing.T) {
	msgs := pb.File_seawise_tunnel_v1_tunnel_proto.Messages()
	for i := 0; i < msgs.Len(); i++ {
		fields := msgs.Get(i).Fields()
		for j := 0; j < fields.Len(); j++ {
			fd := fields.Get(j)
			if fd.Number() >= 32 {
				t.Errorf("%s: field number %d is beyond the scanner's table", fd.FullName(), fd.Number())
			}
			switch fd.Kind() {
			case protoreflect.StringKind, protoreflect.BytesKind:
				if _, ok := fieldCaps[fd.FullName()]; !ok {
					t.Errorf("%s has no cap", fd.FullName())
				}
			case protoreflect.MessageKind, protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Int64Kind, protoreflect.EnumKind:
			default:
				t.Errorf("%s has unsupported kind %s", fd.FullName(), fd.Kind())
			}
			if fd.Cardinality() == protoreflect.Repeated && countCaps[fd.FullName()] == 0 {
				t.Errorf("%s has no count cap", fd.FullName())
			}
		}
	}
	for name := range fieldCaps {
		if d, _ := pb.File_seawise_tunnel_v1_tunnel_proto.Messages().ByName(protoreflect.Name(strings.Split(string(name), ".")[3])), name; d == nil {
			t.Errorf("cap for unknown message %s", name)
		}
	}
}

func TestAppendControlFrame(t *testing.T) {
	if _, err := AppendControlFrame(nil, nil); CodeOf(err) != CodeEmpty {
		t.Fatal(err)
	}
	if _, err := AppendControlFrame(nil, make([]byte, MaxControlMessage+1)); CodeOf(err) != CodeTooLarge {
		t.Fatal(err)
	}
	f, err := AppendControlFrame([]byte{9}, make([]byte, MaxControlMessage))
	if err != nil || len(f) != 1+4+MaxControlMessage || !bytes.Equal(f[:5], []byte{9, 0, 1, 0, 0}) {
		t.Fatal("bad frame", err)
	}
	r := NewControlReader(bytes.NewReader(f[1:]), nil)
	m, err := r.Next()
	if err != nil || len(m) != MaxControlMessage {
		t.Fatal(err)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatal(err)
	}
}

func TestPartialFrameTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var deadlines []time.Time
	r := NewControlReader(a, func(d time.Time) error {
		deadlines = append(deadlines, d)
		return a.SetReadDeadline(d)
	})
	start := time.Now()
	r.now = func() time.Time { return start.Add(-PartialFrameTimeout + 50*time.Millisecond) }
	go b.Write([]byte{0, 0})
	_, err := r.Next()
	wantCode(t, err, CodeTimeout)
	if len(deadlines) != 2 || !deadlines[0].IsZero() || !deadlines[1].Equal(start.Add(50*time.Millisecond)) {
		t.Fatalf("deadlines %v", deadlines)
	}
}

func TestControlReaderIdleHasNoDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	var set []time.Time
	r := NewControlReader(a, func(d time.Time) error { set = append(set, d); return a.SetReadDeadline(d) })
	go func() {
		time.Sleep(30 * time.Millisecond)
		f, _ := AppendControlFrame(nil, []byte{1, 2, 3})
		b.Write(f)
	}()
	m, err := r.Next()
	if err != nil || !bytes.Equal(m, []byte{1, 2, 3}) {
		t.Fatal(err)
	}
	if !set[0].IsZero() {
		t.Fatal("idle read had a deadline")
	}
}

type failDeadline struct{ n, fail int }

func (f *failDeadline) set(time.Time) error {
	f.n++
	if f.n == f.fail {
		return io.ErrClosedPipe
	}
	return nil
}

func TestControlReaderDeadlineErrors(t *testing.T) {
	for _, n := range []int{1, 2} {
		fd := &failDeadline{fail: n}
		r := NewControlReader(bytes.NewReader([]byte{0, 0, 0, 1, 1}), fd.set)
		if _, err := r.Next(); err != io.ErrClosedPipe {
			t.Fatalf("fail %d: %v", n, err)
		}
	}
}

func TestReadErrPassesOtherErrors(t *testing.T) {
	r := NewControlReader(io.MultiReader(bytes.NewReader([]byte{0}), errReader{}), nil)
	if _, err := r.Next(); err != io.ErrClosedPipe {
		t.Fatal(err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestEncodeControlRoundTrip(t *testing.T) {
	for k, body := range agentKinds() {
		b, err := EncodeControl(msgWith(1, 5, body), FromAgent)
		if err != nil {
			t.Fatal(k, err)
		}
		m, err := DecodeControl(b, FromAgent)
		if err != nil || m.Seq != 5 || protoKind(m.Body) != k {
			t.Fatal(k, err)
		}
		if _, err := EncodeControl(msgWith(1, 5, body), FromEdge); CodeOf(err) != CodeDirection && k != "error" {
			t.Fatal(k, err)
		}
	}
	for k, body := range edgeKinds() {
		if _, err := EncodeControl(msgWith(1, 1, body), FromEdge); err != nil {
			t.Fatal(k, err)
		}
	}
	_, err := EncodeControl(&pb.ControlMessage{Schema: 1, Seq: 1}, FromAgent)
	wantCode(t, err, CodeNoBody)
	_, err = EncodeControl(&pb.ControlMessage{Schema: 1, Seq: 1, Body: &pb.ControlMessage_Error{Error: &pb.Error{Detail: string([]byte{0xff})}}}, FromAgent)
	wantCode(t, err, CodeBadValue)
	_, err = DecodeControl(nil, FromAgent)
	wantCode(t, err, CodeEmpty)
	_, err = DecodeControl(make([]byte, MaxControlMessage+1), FromAgent)
	wantCode(t, err, CodeTooLarge)
}

func TestValidateBodyDefault(t *testing.T) {
	wantCode(t, validateBody(&pb.ControlMessage{}), CodeNoBody)
}

func TestHelloBodyRules(t *testing.T) {
	good := fx.HelloBody()
	b, err := EncodeHelloBody(good)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := DecodeHelloBody(b); err != nil || !proto.Equal(h, good) {
		t.Fatal(err)
	}
	bad := map[string]func(*pb.HelloBody){
		"server_id":      func(h *pb.HelloBody) { h.ServerId = h.ServerId[:15] },
		"key_id":         func(h *pb.HelloBody) { h.KeyId = h.KeyId[:42] + "!" },
		"run_id":         func(h *pb.HelloBody) { h.RunId = nil },
		"caps-unsorted":  func(h *pb.HelloBody) { h.Capabilities = []string{"b", "a"} },
		"caps-dup":       func(h *pb.HelloBody) { h.Capabilities = []string{"a", "a"} },
		"caps-upper":     func(h *pb.HelloBody) { h.Capabilities = []string{"A"} },
		"caps-empty":     func(h *pb.HelloBody) { h.Capabilities = []string{""} },
		"version":        func(h *pb.HelloBody) { h.AgentVersion = "v2" },
		"transport":      func(h *pb.HelloBody) { h.Transport = 0 },
		"time_nonce":     func(h *pb.HelloBody) { h.TimeNonce = h.TimeNonce[:8] },
		"routes_held":    func(h *pb.HelloBody) { h.RoutesHeld = 1001 },
		"max_streams-0":  func(h *pb.HelloBody) { h.MaxStreams = 0 },
		"max_streams-hi": func(h *pb.HelloBody) { h.MaxStreams = 4097 },
	}
	for name, f := range bad {
		h := proto.Clone(good).(*pb.HelloBody)
		f(h)
		if _, err := EncodeHelloBody(h); CodeOf(err) != CodeBadValue {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := map[string]func(*pb.HelloBody){
		"routes_held-1000": func(h *pb.HelloBody) { h.RoutesHeld = 1000 },
		"max_streams-1":    func(h *pb.HelloBody) { h.MaxStreams = 1 },
		"max_streams-4096": func(h *pb.HelloBody) { h.MaxStreams = 4096 },
		"websocket":        func(h *pb.HelloBody) { h.Transport = pb.Transport_TRANSPORT_WEBSOCKET },
		"caps-32":          func(h *pb.HelloBody) { h.Capabilities = caps(32) },
	}
	for name, f := range ok {
		h := proto.Clone(good).(*pb.HelloBody)
		f(h)
		if _, err := EncodeHelloBody(h); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	h := proto.Clone(good).(*pb.HelloBody)
	h.Capabilities = caps(33)
	_, err = EncodeHelloBody(h)
	wantCode(t, err, CodeTooLarge)
	_, err = DecodeHelloBody(nil)
	wantCode(t, err, CodeEmpty)
	_, err = DecodeHelloBody(make([]byte, MaxHelloBody+1))
	wantCode(t, err, CodeTooLarge)
	_, err = DecodeHelloBody([]byte{0x58, 0x01})
	wantCode(t, err, CodeUnknownField)
	_, err = EncodeHelloBody(&pb.HelloBody{AgentVersion: string([]byte{0xff})})
	wantCode(t, err, CodeBadValue)
}

func caps(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "c" + string(rune('a'+i/26)) + string(rune('a'+i%26))
	}
	return out
}

func TestHelloAckBodyRules(t *testing.T) {
	good := fx.HelloAckBody([]byte("x"))
	b, err := EncodeHelloAckBody(good)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := DecodeHelloAckBody(b); err != nil || !proto.Equal(h, good) {
		t.Fatal(err)
	}
	bad := map[string]func(*pb.HelloAckBody){
		"session_id":    func(h *pb.HelloAckBody) { h.SessionId = nil },
		"edge_id":       func(h *pb.HelloAckBody) { h.EdgeId = "edge-us-east" },
		"caps":          func(h *pb.HelloAckBody) { h.Capabilities = []string{"b", "a"} },
		"digest":        func(h *pb.HelloAckBody) { h.OfferedDigest = h.OfferedDigest[:31] },
		"streams-0":     func(h *pb.HelloAckBody) { h.MaxStreams = 0 },
		"streams-4097":  func(h *pb.HelloAckBody) { h.MaxStreams = 4097 },
		"control-bytes": func(h *pb.HelloAckBody) { h.MaxControlBytes = 65535 },
		"age-low":       func(h *pb.HelloAckBody) { h.MaxSessionAgeS = 43199 },
		"age-high":      func(h *pb.HelloAckBody) { h.MaxSessionAgeS = 86401 },
	}
	for name, f := range bad {
		h := proto.Clone(good).(*pb.HelloAckBody)
		f(h)
		if _, err := EncodeHelloAckBody(h); CodeOf(err) != CodeBadValue {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, age := range []int64{43200, 86400} {
		h := proto.Clone(good).(*pb.HelloAckBody)
		h.MaxSessionAgeS = age
		h.MaxStreams = 4096
		if _, err := EncodeHelloAckBody(h); err != nil {
			t.Error(age, err)
		}
	}
	_, err = DecodeHelloAckBody(nil)
	wantCode(t, err, CodeEmpty)
	_, err = DecodeHelloAckBody(make([]byte, MaxHelloAckBody+1))
	wantCode(t, err, CodeTooLarge)
	_, err = DecodeHelloAckBody([]byte{0x58, 0x01})
	wantCode(t, err, CodeUnknownField)
	_, err = EncodeHelloAckBody(&pb.HelloAckBody{EdgeId: string([]byte{0xff})})
	wantCode(t, err, CodeBadValue)
}

func TestStreamHeaderEncode(t *testing.T) {
	h := fx.StreamHeader()
	h.ClientIp = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}
	f, err := AppendStreamHeader([]byte{7}, h, nil)
	if err != nil || f[0] != 7 {
		t.Fatal(err)
	}
	got, err := ReadStreamHeader(bytes.NewReader(f[1:]), nil)
	if err != nil || !bytes.Equal(got.ClientIp, []byte{1, 2, 3, 4}) {
		t.Fatal(err)
	}
	if len(h.ClientIp) != 16 {
		t.Fatal("encode changed the caller's header")
	}
	h.Version = 2
	_, err = AppendStreamHeader(nil, h, nil)
	wantCode(t, err, CodeBadValue)
	_, err = EncodeStreamHeader(&pb.StreamHeader{Alpn: string([]byte{0xff})}, nil)
	wantCode(t, err, CodeBadValue)
	_, err = DecodeStreamHeader(nil, nil)
	wantCode(t, err, CodeEmpty)
	_, err = DecodeStreamHeader(make([]byte, MaxHeader+1), nil)
	wantCode(t, err, CodeTooLarge)
	_, err = ReadStreamHeader(bytes.NewReader([]byte{0, 0}), nil)
	wantCode(t, err, CodeEmpty)
}

func TestNormaliseIP(t *testing.T) {
	mapped := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}
	for i := 0; i < 12; i++ {
		ip := append([]byte(nil), mapped...)
		ip[i] ^= 1
		if len(normaliseIP(ip)) != 16 {
			t.Errorf("byte %d changed but address was cut", i)
		}
	}
	if !bytes.Equal(normaliseIP(mapped), []byte{1, 2, 3, 4}) {
		t.Fatal("mapped address not cut")
	}
	if len(normaliseIP([]byte{1, 2, 3, 4})) != 4 {
		t.Fatal("ipv4 changed")
	}
}

func TestStreamReply(t *testing.T) {
	f, err := AppendStreamReply([]byte{9}, pb.ReplyCode_AGENT_BUSY)
	if err != nil || !bytes.Equal(f, []byte{9, 0, 2, 0x08, 0x05}) {
		t.Fatalf("%x %v", f, err)
	}
	if _, err := AppendStreamReply(nil, 0); CodeOf(err) != CodeEmpty {
		t.Fatal(err)
	}
	if _, err := AppendStreamReply(nil, 77); CodeOf(err) != CodeBadValue {
		t.Fatal(err)
	}
	_, err = DecodeStreamReply(make([]byte, MaxReply+1))
	wantCode(t, err, CodeTooLarge)
	_, err = DecodeStreamReply(nil)
	wantCode(t, err, CodeEmpty)
	_, err = ReadStreamReply(bytes.NewReader([]byte{0}))
	wantCode(t, err, CodeTruncated)
}

func relayPrefix() *pb.RelayPrefix {
	return &pb.RelayPrefix{Version: 1, ServerId: fx.UUID(fx.Server1), ExpectedEpoch: 4, IngressEdgeId: fx.EdgeA, Hop: 1}
}

func TestRelayPrefix(t *testing.T) {
	f, err := AppendRelayPrefix([]byte{1}, relayPrefix())
	if err != nil || f[0] != 1 {
		t.Fatal(err)
	}
	p, err := ReadRelayPrefix(bytes.NewReader(f[1:]), fx.EdgeA)
	if err != nil || !proto.Equal(p, relayPrefix()) {
		t.Fatal(err)
	}
	_, err = ReadRelayPrefix(bytes.NewReader(f[1:]), fx.EdgeB)
	wantCode(t, err, CodeWrongPeer)
	bad := map[string]func(*pb.RelayPrefix){
		"version": func(p *pb.RelayPrefix) { p.Version = 2 },
		"server":  func(p *pb.RelayPrefix) { p.ServerId = p.ServerId[:15] },
		"epoch":   func(p *pb.RelayPrefix) { p.ExpectedEpoch = 0 },
		"ingress": func(p *pb.RelayPrefix) { p.IngressEdgeId = "edge" },
		"hop-2":   func(p *pb.RelayPrefix) { p.Hop = 2 },
		"hop-0":   func(p *pb.RelayPrefix) { p.Hop = 0 },
	}
	for name, mut := range bad {
		p := relayPrefix()
		mut(p)
		if _, err := AppendRelayPrefix(nil, p); CodeOf(err) != CodeBadValue {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err = AppendRelayPrefix(nil, &pb.RelayPrefix{IngressEdgeId: string([]byte{0xff})})
	wantCode(t, err, CodeBadValue)
	_, err = DecodeRelayPrefix(nil, fx.EdgeA)
	wantCode(t, err, CodeEmpty)
	_, err = DecodeRelayPrefix(make([]byte, MaxRelayPrefix+1), fx.EdgeA)
	wantCode(t, err, CodeTooLarge)
	_, err = DecodeRelayPrefix([]byte{0x30, 0x01}, fx.EdgeA)
	wantCode(t, err, CodeUnknownField)
	_, err = ReadRelayPrefix(bytes.NewReader([]byte{0, 0}), fx.EdgeA)
	wantCode(t, err, CodeEmpty)
}

func TestFrame16(t *testing.T) {
	if _, err := appendFrame16(nil, nil, 4, "x"); CodeOf(err) != CodeEmpty {
		t.Fatal(err)
	}
	if _, err := appendFrame16(nil, make([]byte, 5), 4, "x"); CodeOf(err) != CodeTooLarge {
		t.Fatal(err)
	}
	f, _ := appendFrame16(nil, make([]byte, 4), 4, "x")
	if _, err := readFrame16(bytes.NewReader(f), 4, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame16(bytes.NewReader(f), 3, "x"); CodeOf(err) != CodeTooLarge {
		t.Fatal(err)
	}
	if _, err := readFrame16(bytes.NewReader(f[:4]), 4, "x"); CodeOf(err) != CodeTruncated {
		t.Fatal(err)
	}
}

func TestTwinPath(t *testing.T) {
	m, p, err := TwinPath(pb.DeviceMethod_LIST_APPS, "")
	if err != nil || m != "GET" || p != "/device/v2/apps" {
		t.Fatal(m, p, err)
	}
	if _, _, err := TwinPath(pb.DeviceMethod_LIST_APPS, "x"); CodeOf(err) != CodeBadValue {
		t.Fatal(err)
	}
	if _, _, err := TwinPath(0, ""); CodeOf(err) != CodeBadValue {
		t.Fatal(err)
	}
	DeviceRoutes[99] = DeviceRoute{Method: "PUT", Path: "/device/v2/apps", Param: true}
	defer delete(DeviceRoutes, 99)
	if _, p, err := TwinPath(99, "app-1"); err != nil || p != "/device/v2/apps/app-1" {
		t.Fatal(p, err)
	}
	for _, s := range []string{"", "a/b", "A", fx.Repeat("a", 257)} {
		if _, _, err := TwinPath(99, s); CodeOf(err) != CodeBadValue {
			t.Errorf("%q: %v", s, err)
		}
	}
	for m := range pb.DeviceMethod_name {
		if m == 0 {
			continue
		}
		if _, ok := DeviceRoutes[pb.DeviceMethod(m)]; !ok {
			t.Errorf("method %d has no HTTPS twin", m)
		}
	}
}

func TestSeq(t *testing.T) {
	var out SeqOut
	var in SeqIn
	for i := uint64(1); i <= 3; i++ {
		if n := out.Next(); n != i || in.Accept(n) != nil {
			t.Fatal(i)
		}
	}
	wantCode(t, in.Accept(3), CodeSeq)
	wantCode(t, in.Accept(5), CodeSeq)
	if in.Accept(4) != nil {
		t.Fatal("next refused after errors")
	}
}

func TestTextRules(t *testing.T) {
	type tc struct {
		ok bool
		f  bool
	}
	cases := map[string]tc{
		"edge-us-east-1":     {true, ValidEdgeID("edge-us-east-1")},
		"edge-us-east-1234":  {true, ValidEdgeID("edge-us-east-1234")},
		"edge-us-east-12345": {false, ValidEdgeID("edge-us-east-12345")},
		"edge-US-east-1":     {false, ValidEdgeID("edge-US-east-1")},
		"edge-long":          {false, ValidEdgeID("edge-" + fx.Repeat("a", 60) + "-b-1")},
		"x-edge-a-b-1":       {false, ValidEdgeID("x-edge-a-b-1")},
		"semver":             {true, ValidAgentVersion("10.20.30")},
		"semver-pre":         {true, ValidAgentVersion("1.0.0-alpha.1")},
		"semver-pre-zero":    {false, ValidAgentVersion("1.0.0-01")},
		"semver-empty":       {false, ValidAgentVersion("")},
		"semver-32":          {true, ValidAgentVersion("1.0.0-" + fx.Repeat("a", 26))},
		"semver-33":          {false, ValidAgentVersion("1.0.0-" + fx.Repeat("a", 27))},
		"token":              {true, ValidToken("a-b_c.9", 7)},
		"token-long":         {false, ValidToken("abc", 2)},
		"token-at-max":       {true, ValidToken("ab", 2)},
		"token-slash":        {false, ValidToken("a/b", 9)},
		"token-boundaries":   {true, ValidToken("az09", 9)},
		"token-upper":        {false, ValidToken("Z", 9)},
		"token-colon":        {false, ValidToken(":", 9)},
		"token-at":           {false, ValidToken("@", 9)},
		"token-brace":        {false, ValidToken("{", 9)},
		"token-backtick":     {false, ValidToken("`", 9)},
		"token-slash-only":   {false, ValidToken("/", 9)},
		"kid":                {true, ValidKeyID(strings.Repeat("A", 43))},
		"kid-non-canonical":  {false, ValidKeyID(strings.Repeat("A", 42) + "B")},
		"kid-44":             {false, ValidKeyID(strings.Repeat("A", 44))},
		"kid-bad":            {false, ValidKeyID(strings.Repeat("A", 42) + "+")},
		"jws":                {true, ValidCompactJWS("a.b.c", 5)},
		"jws-long":           {false, ValidCompactJWS("a.b.c", 4)},
		"jws-empty-seg":      {false, ValidCompactJWS("a..c", 9)},
		"jws-empty-last":     {false, ValidCompactJWS("a.b.", 9)},
		"jws-empty-first":    {false, ValidCompactJWS(".b.c", 9)},
		"jws-four":           {false, ValidCompactJWS("a.b.c.d", 9)},
		"jws-two":            {false, ValidCompactJWS("a.b", 9)},
		"jws-pad":            {false, ValidCompactJWS("a.b.c=", 9)},
		"jws-alphabet":       {true, ValidCompactJWS("AZaz09-_.x.y", 99)},
		"jws-plus":           {false, ValidCompactJWS("a+.b.c", 9)},
		"jws-at":             {false, ValidCompactJWS("@.b.c", 9)},
		"jws-bracket":        {false, ValidCompactJWS("[.b.c", 9)},
		"jws-colon":          {false, ValidCompactJWS(":.b.c", 9)},
		"jws-backtick":       {false, ValidCompactJWS("`.b.c", 9)},
		"jws-brace":          {false, ValidCompactJWS("{.b.c", 9)},
		"jws-slash":          {false, ValidCompactJWS("/.b.c", 9)},
		"detail":             {true, validDetail(" ~")},
		"detail-del":         {false, validDetail("\x7f")},
		"detail-us":          {false, validDetail("\x1f")},
		"detail-128":         {true, validDetail(fx.Repeat("x", 128))},
		"nonce":              {true, validNonce("!#[]~")},
		"nonce-quote":        {false, validNonce("\"")},
		"nonce-backslash":    {false, validNonce("\\")},
		"nonce-space":        {false, validNonce(" ")},
		"nonce-del":          {false, validNonce("\x7f")},
		"nonce-256":          {true, validNonce(fx.Repeat("a", 256))},
		"caps-33":            {false, ValidCapabilities(caps(33))},
		"caps-long":          {false, ValidCapabilities([]string{fx.Repeat("a", 33)})},
	}
	for name, c := range cases {
		if c.ok != c.f {
			t.Errorf("%s: got %v", name, c.f)
		}
	}
}

func TestAllowedFrom(t *testing.T) {
	for k, b := range agentKinds() {
		m := msgWith(0, 0, b)
		if !allowedFrom(m, FromAgent) || (k != "error" && allowedFrom(m, FromEdge)) {
			t.Error(k)
		}
	}
	for k, b := range edgeKinds() {
		m := msgWith(0, 0, b)
		if !allowedFrom(m, FromEdge) || (k != "error" && allowedFrom(m, FromAgent)) {
			t.Error(k)
		}
	}
}
