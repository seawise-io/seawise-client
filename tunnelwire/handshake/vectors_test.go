package handshake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

func TestVectorsUpToDate(t *testing.T) {
	update := os.Getenv("UPDATE_VECTORS") == "1"
	for name, f := range map[string]vfile{"hello.json": genHello(), "negotiation.json": genNegotiation(), "relay.json": genRelay()} {
		ok, err := vkeys.Sync(name, vkeys.Pretty(f), update)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("%s is out of date; run with UPDATE_VECTORS=1", name)
		}
	}
}

func load(t *testing.T, name string) vfile {
	t.Helper()
	b, err := vkeys.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	var f vfile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	for _, k := range f.Keys {
		if k.X != vkeys.B64(vkeys.Pub(k.Name)) || k.KID != vkeys.KID(k.Name) {
			t.Fatalf("key %s does not match its seed", k.Name)
		}
	}
	return f
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unb64url(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exporterOf(t *testing.T, ctx map[string]any) [32]byte {
	var e [32]byte
	b, err := hex.DecodeString(ctx["exporter"].(string))
	if err != nil || len(b) != 32 {
		t.Fatal("bad exporter")
	}
	copy(e[:], b)
	return e
}

func edgeKeysOf(t *testing.T, ctx map[string]any) EdgeKeys {
	m := map[string]ed25519.PublicKey{}
	for _, k := range ctx["edge_keys"].([]any) {
		e := k.(map[string]any)
		m[e["edge_id"].(string)] = unb64url(t, e["x"].(string))
	}
	return func(id string) (ed25519.PublicKey, bool) { k, ok := m[id]; return k, ok }
}

func strings_(v any) []string {
	out := []string{}
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func normJSON(v any) string {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	out, _ := json.Marshal(x)
	return string(out)
}

func checkResult(t *testing.T, c vcase, got any) {
	t.Helper()
	if c.Result != nil && normJSON(c.Result) != normJSON(got) {
		t.Errorf("%s: result %s, want %s", c.Name, normJSON(got), normJSON(c.Result))
	}
}

func runAck(t *testing.T, c vcase) (string, any) {
	a := &pb.HelloAck{}
	if err := proto.Unmarshal(unb64(t, c.Input), a); err != nil {
		t.Fatal(err)
	}
	sentBody := unb64(t, c.Context["sent_body"].(string))
	sent, err := wire.DecodeHelloBody(sentBody)
	if err != nil {
		t.Fatal(err)
	}
	ex := exporterOf(t, c.Context)
	acc, err := VerifyHelloAck(a, ex, Sent{Body: sentBody, Hello: sent, Required: strings_(c.Context["required"])}, edgeKeysOf(t, c.Context))
	if err != nil {
		return string(CodeOf(err)), nil
	}
	return "ok", map[string]any{
		"signed_message":   hex.EncodeToString(AckMessage(ex, a.Body)),
		"ping_interval_ms": acc.PingInterval.Milliseconds(),
		"ping_timeout_ms":  acc.PingTimeout.Milliseconds(),
		"max_streams":      acc.Ack.MaxStreams,
		"edge_id":          acc.Ack.EdgeId,
	}
}

func TestHelloVectors(t *testing.T) {
	for _, c := range load(t, "hello.json").Cases {
		var got string
		var res any
		switch c.Kind {
		case "hello":
			h := &pb.Hello{}
			if err := proto.Unmarshal(unb64(t, c.Input), h); err != nil {
				t.Fatal(err)
			}
			devs := map[string]Device{}
			for _, e := range c.Context["registry"].([]any) {
				r := e.(map[string]any)
				devs[r["kid"].(string)] = Device{PublicKey: unb64url(t, r["x"].(string)), ServerID: fx.UUID(r["server_id"].(string)), Status: r["status"].(string)}
			}
			ex := exporterOf(t, c.Context)
			_, code := CheckHello(h, ex, pb.Transport(pb.Transport_value[c.Context["transport"].(string)]), func(k string) (Device, bool) { d, ok := devs[k]; return d, ok })
			got = code.String()
			if code == pb.RefuseCode_REFUSE_UNSPECIFIED {
				got = "ok"
				res = map[string]string{"signed_message": hex.EncodeToString(HelloMessage(ex, h.Body))}
			}
		case "hello_ack":
			got, res = runAck(t, c)
		case "supersede":
			o, _ := hex.DecodeString(c.Context["old_run_id"].(string))
			n, _ := hex.DecodeString(c.Context["new_run_id"].(string))
			got = "no_message"
			if Supersedes(o, n) {
				got = "drain_superseded_stop"
			}
		default:
			t.Fatalf("%s: unknown kind %s", c.Name, c.Kind)
		}
		if got != c.Expect {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			continue
		}
		checkResult(t, c, res)
	}
}

func TestNegotiationVectors(t *testing.T) {
	for _, c := range load(t, "negotiation.json").Cases {
		switch c.Kind {
		case "negotiate":
			minor, caps := Negotiate(uint32(c.Context["agent_minor"].(float64)), strings_(c.Context["agent_capabilities"]), uint32(c.Context["edge_minor"].(float64)), strings_(c.Context["edge_capabilities"]))
			checkResult(t, c, map[string]any{"protocol_minor": minor, "capabilities": caps})
		case "hello_ack":
			if got, _ := runAck(t, c); got != c.Expect {
				t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			}
		default:
			t.Fatalf("%s: unknown kind %s", c.Name, c.Kind)
		}
	}
}

func codeStr(err error) string {
	switch {
	case err == nil:
		return "ok"
	case CodeOf(err) != "":
		return string(CodeOf(err))
	case wire.CodeOf(err) != "":
		return string(wire.CodeOf(err))
	}
	return "uncoded"
}

func TestRelayVectors(t *testing.T) {
	for _, c := range load(t, "relay.json").Cases {
		switch c.Kind {
		case "peer":
			tr := c.Context["transcript"].(map[string]any)
			d, err := ReadPeerHello(bytes.NewReader(unb64(t, tr["dialer_hello"].(string))))
			if err != nil {
				t.Fatal(err)
			}
			a, err := ReadPeerHello(bytes.NewReader(unb64(t, tr["acceptor_hello"].(string))))
			if err != nil {
				t.Fatal(err)
			}
			keys := edgeKeysOf(t, c.Context)
			gotA := codeStr(CheckPeer(a, d, RoleAcceptor, unb64(t, tr["dialer_sig"].(string)), "", keys))
			gotD := codeStr(CheckPeer(d, a, RoleDialer, unb64(t, tr["acceptor_sig"].(string)), c.Context["dialed"].(string), keys))
			if gotA != c.Context["acceptor_check"] || gotD != c.Expect {
				t.Errorf("%s: acceptor %s dialer %s, want %s %s", c.Name, gotA, gotD, c.Context["acceptor_check"], c.Expect)
			}
			if c.Result != nil {
				checkResult(t, c, map[string]string{
					"dialer_message":   hex.EncodeToString(PeerMessage(d, a, RoleDialer)),
					"acceptor_message": hex.EncodeToString(PeerMessage(d, a, RoleAcceptor)),
				})
			}
		case "peer_hello":
			_, err := ReadPeerHello(bytes.NewReader(unb64(t, c.Input)))
			if got := codeStr(err); got != c.Expect {
				t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			}
		case "relay_prefix":
			_, err := wire.ReadRelayPrefix(bytes.NewReader(unb64(t, c.Input)), c.Context["peer"].(string))
			if got := codeStr(err); got != c.Expect {
				t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
			}
		default:
			t.Fatalf("%s: unknown kind %s", c.Name, c.Kind)
		}
	}
}

var _ = sha256.Sum256
