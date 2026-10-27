package claims

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/edkey"
	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func TestVectorsUpToDate(t *testing.T) {
	update := os.Getenv("UPDATE_VECTORS") == "1"
	files := map[string]vfile{"routeset.json": genRouteSet(), "flags.json": genFlags(), "signed_state.json": genSignedState(), "device_call.json": genDeviceCall()}
	for name, f := range files {
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
	return f
}

func keyMap(f vfile) map[string]ed25519.PublicKey {
	m := map[string]ed25519.PublicKey{}
	for _, k := range f.Keys {
		m[k.Name] = vkeys.Pub(k.Name)
	}
	return m
}

func codeStr(err error) string {
	if err == nil {
		return "ok"
	}
	if c := CodeOf(err); c != "" {
		return string(c)
	}
	return err.Error()
}

func normJSON(v any) string {
	b, _ := json.Marshal(v)
	var x any
	_ = json.Unmarshal(b, &x)
	out, _ := json.Marshal(x)
	return string(out)
}

func expectCase(t *testing.T, c vcase, got string, res any) {
	t.Helper()
	if got != c.Expect {
		t.Errorf("%s: got %s, want %s", c.Name, got, c.Expect)
		return
	}
	if c.Result != nil && normJSON(c.Result) != normJSON(res) {
		t.Errorf("%s: result %s, want %s", c.Name, normJSON(res), normJSON(c.Result))
	}
}

func TestRouteSetVectors(t *testing.T) {
	f := load(t, "routeset.json")
	edges := map[string]ed25519.PublicKey{fx.EdgeA: vkeys.Pub(fx.EdgeA), fx.EdgeB: vkeys.Pub(fx.EdgeB)}
	control := map[string]ed25519.PublicKey{"control-1": vkeys.Pub("control-1")}
	for _, c := range f.Cases {
		switch c.Kind {
		case "routeset":
			payload, signer, err := vkeys.VerifyJWS(c.Input, TypRouteSet, edges)
			if err != nil {
				t.Fatal(c.Name, err)
			}
			sid, _ := hex.DecodeString(c.Context["session_id"].(string))
			_, err = CheckRouteSet(payload, RouteSetExpect{EdgeID: c.Context["edge_id"].(string), Signer: signer, ServerID: c.Context["server_id"].(string), SessionID: sid, LastVersion: int64(c.Context["last_version"].(float64))})
			expectCase(t, c, codeStr(err), nil)
		case "routeset_size":
			expectCase(t, c, codeStr(CheckRouteSetSize(c.Input)), nil)
		case "signed_time":
			payload, _, err := vkeys.VerifyJWS(c.Input, TypTime, control)
			if err != nil {
				t.Fatal(c.Name, err)
			}
			tn, _ := hex.DecodeString(c.Context["time_nonce"].(string))
			_, err = CheckSignedTime(payload, c.Context["server_id"].(string), TimeNonce(tn))
			expectCase(t, c, codeStr(err), nil)
		default:
			t.Fatalf("%s: kind %s", c.Name, c.Kind)
		}
	}
}

func TestFlagsVectors(t *testing.T) {
	f := load(t, "flags.json")
	keys := keyMap(f)
	for _, c := range f.Cases {
		if c.Kind == "flags_size" {
			expectCase(t, c, codeStr(CheckFlagsSize(c.Input)), nil)
			continue
		}
		payload, _, err := vkeys.VerifyJWS(c.Input, TypFlags, keys)
		if err != nil {
			t.Fatal(c.Name, err)
		}
		fl, err := ParseFlags(payload)
		if err == nil {
			err = AcceptNewer(int64(c.Context["last_generation"].(float64)), fl)
		}
		var res any
		if err == nil {
			modes := map[string]any{}
			for _, s := range c.Context["servers"].([]any) {
				modes[s.(string)] = fl.Mode(fx.UUID(s.(string))).String()
			}
			res = map[string]any{"modes": modes, "hashed": map[string]string{fx.Server1: HashedID(fl.salt, fx.UUID(fx.Server1)), fx.Server2: HashedID(fl.salt, fx.UUID(fx.Server2))}}
		}
		expectCase(t, c, codeStr(err), res)
	}
}

func TestSignedStateVectors(t *testing.T) {
	f := load(t, "signed_state.json")
	control := map[string]ed25519.PublicKey{"control-1": vkeys.Pub("control-1")}
	for _, c := range f.Cases {
		payload, _, err := vkeys.VerifyJWS(c.Input, TypState, control)
		if err != nil {
			expectCase(t, c, err.Error(), nil)
			continue
		}
		st, err := CheckSignedState(payload, c.Context["server_id"].(string), c.Context["key_id"].(string), c.Context["nonce"].(string))
		var res any
		if err == nil {
			res = map[string]any{"hold": st.Holds(), "clears": st.Clears()}
		}
		expectCase(t, c, codeStr(err), res)
	}
}

func TestDeviceCallVectors(t *testing.T) {
	f := load(t, "device_call.json")
	for _, c := range f.Cases {
		switch c.Kind {
		case "relayed_call":
			b, _ := base64.StdEncoding.DecodeString(c.Input)
			call := &pb.DeviceCall{}
			if err := proto.Unmarshal(b, call); err != nil {
				t.Fatal(err)
			}
			payload, pub, err := vkeys.VerifyJWK(call.Dpop, "dpop+jwt")
			if err != nil {
				t.Fatal(c.Name, err)
			}
			cl, err := ParseDPoPClaims(payload)
			if err != nil {
				t.Fatal(c.Name, err)
			}
			err = CheckRelayedProof(call, c.Context["origin"].(string), edkey.KeyID(pub), c.Context["server_kid"].(string), cl, c.Context["nonce"].(string))
			var res any
			if err == nil && c.Result != nil {
				res = map[string]string{"htm": cl.HTM, "htu": cl.HTU, "body_sha256": cl.BodySHA256}
			}
			if CodeOf(err) == CodeUseNonce {
				res = map[string]int{"http_status": 401}
			}
			expectCase(t, c, codeStr(err), res)
		case "dedupe":
			body, _ := base64.StdEncoding.DecodeString(c.Context["body"].(string))
			var st *Stored
			if h, ok := c.Context["stored_body_sha256"].(string); ok {
				st = &Stored{}
				d, _ := hex.DecodeString(h)
				copy(st.BodySHA256[:], d)
			}
			expectCase(t, c, string(Dedupe(st, body)), nil)
		case "scope":
			key, _ := hex.DecodeString(c.Context["key"].(string))
			expectCase(t, c, "ok", DedupeScope(c.Context["server_id"].(string), pb.DeviceMethod(pb.DeviceMethod_value[c.Context["method"].(string)]), c.Context["path"].(string), key))
		default:
			t.Fatalf("%s: kind %s", c.Name, c.Kind)
		}
	}
}
