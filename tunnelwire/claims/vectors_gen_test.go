package claims

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

type vcase struct {
	Name    string         `json:"name"`
	Kind    string         `json:"kind,omitempty"`
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

const (
	vecNow    = int64(1793000000)
	controlK  = "control-1"
	origin    = "https://api.seawise.io"
	vecNonce  = "n1.AAAAAQ.c2VydmVyLW5vbmNl"
	vecNonce2 = "n1.AAAAAg.c2VydmVyLW5vbmNl"
)

func sessionID() []byte { return fx.Bytes("session-1", 16) }

func routes(n int) []map[string]any {
	out := []map[string]any{}
	for i := 0; i < n; i++ {
		id := fx.UUIDString(fx.Bytes(fmt.Sprintf("app-%d", i), 16))
		out = append(out, map[string]any{"app_id": id, "fqdn": fmt.Sprintf("app%d.example.seawise.dev", i), "public": i%2 == 0, "access_version": i})
	}
	return out
}

func rsClaims(f func(map[string]any)) map[string]any {
	c := map[string]any{
		"edge": fx.EdgeA, "server_id": fx.Server1, "session_id": base64.RawURLEncoding.EncodeToString(sessionID()),
		"version": 5, "routes": routes(2), "iat": vecNow,
	}
	if f != nil {
		f(c)
	}
	return c
}

func genRouteSet() vfile {
	var cs []vcase
	ctx := func(last int64) map[string]any {
		return map[string]any{"edge_id": fx.EdgeA, "server_id": fx.Server1, "session_id": hex.EncodeToString(sessionID()), "last_version": last}
	}
	add := func(name, key string, claims any, c map[string]any, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "routeset", Input: vkeys.SignJWS(vkeys.Key(key), TypRouteSet, claims), Context: c, Expect: expect})
	}
	add("valid", fx.EdgeA, rsClaims(nil), ctx(0), "ok")
	add("valid-empty-routes", fx.EdgeA, rsClaims(func(c map[string]any) { c["routes"] = []any{} }), ctx(0), "ok")
	add("valid-after-version-4", fx.EdgeA, rsClaims(nil), ctx(4), "ok")
	add("version-going-backwards", fx.EdgeA, rsClaims(nil), ctx(6), "rollback")
	add("version-repeated", fx.EdgeA, rsClaims(nil), ctx(5), "rollback")
	add("wrong-edge-claim", fx.EdgeA, rsClaims(func(c map[string]any) { c["edge"] = fx.EdgeB }), ctx(0), "wrong_edge")
	add("signed-by-other-edge", fx.EdgeB, rsClaims(nil), ctx(0), "wrong_edge")
	add("wrong-server", fx.EdgeA, rsClaims(func(c map[string]any) { c["server_id"] = fx.Server2 }), ctx(0), "wrong_server")
	add("wrong-session", fx.EdgeA, rsClaims(func(c map[string]any) {
		c["session_id"] = base64.RawURLEncoding.EncodeToString(fx.Bytes("session-2", 16))
	}), ctx(0), "wrong_session")
	add("routes-250", fx.EdgeA, rsClaims(func(c map[string]any) { c["routes"] = routes(250) }), ctx(0), "ok")
	add("routes-251", fx.EdgeA, rsClaims(func(c map[string]any) { c["routes"] = routes(251) }), ctx(0), "too_many_routes")
	add("duplicate-app", fx.EdgeA, rsClaims(func(c map[string]any) {
		r := routes(2)
		r[1]["app_id"] = r[0]["app_id"]
		c["routes"] = r
	}), ctx(0), "malformed")
	add("duplicate-fqdn", fx.EdgeA, rsClaims(func(c map[string]any) {
		r := routes(2)
		r[1]["fqdn"] = r[0]["fqdn"]
		c["routes"] = r
	}), ctx(0), "malformed")
	add("fqdn-uppercase", fx.EdgeA, rsClaims(func(c map[string]any) { r := routes(1); r[0]["fqdn"] = "App.example.dev"; c["routes"] = r }), ctx(0), "malformed")
	add("route-extra-member", fx.EdgeA, rsClaims(func(c map[string]any) { r := routes(1); r[0]["port"] = 80; c["routes"] = r }), ctx(0), "malformed")
	add("route-missing-member", fx.EdgeA, rsClaims(func(c map[string]any) { r := routes(1); delete(r[0], "public"); c["routes"] = r }), ctx(0), "malformed")
	add("extra-member", fx.EdgeA, rsClaims(func(c map[string]any) { c["exp"] = vecNow }), ctx(0), "malformed")
	add("missing-iat", fx.EdgeA, rsClaims(func(c map[string]any) { delete(c, "iat") }), ctx(0), "malformed")
	add("version-unsafe-integer", fx.EdgeA, rsClaims(func(c map[string]any) { c["version"] = int64(1) << 53 }), ctx(0), "malformed")
	add("version-zero", fx.EdgeA, rsClaims(func(c map[string]any) { c["version"] = 0 }), ctx(0), "malformed")
	add("version-float", fx.EdgeA, rsClaims(func(c map[string]any) { c["version"] = 5.5 }), ctx(0), "malformed")
	dup := `{"edge":"edge-us-east-1","edge":"edge-us-east-1","server_id":"` + fx.Server1 + `","session_id":"` + base64.RawURLEncoding.EncodeToString(sessionID()) + `","version":5,"routes":[],"iat":1}`
	cs = append(cs, vcase{Name: "duplicate-member", Kind: "routeset", Input: vkeys.SignRaw(vkeys.Key(fx.EdgeA), `{"typ":"sw-routeset+jws","alg":"EdDSA","kid":"`+vkeys.KID(fx.EdgeA)+`"}`, dup), Context: ctx(0), Expect: "malformed"})

	// Size is checked before the signature, so any compact JWS shape will do.
	cs = append(cs, vcase{Name: "size-61440", Kind: "routeset_size", Input: fx.JWS(61440), Expect: "ok"})
	cs = append(cs, vcase{Name: "size-61441", Kind: "routeset_size", Input: fx.JWS(61441), Expect: "too_large"})

	// Signed time inside RouteSet.
	tn := fx.HelloBody().TimeNonce
	st := func(name, server string, nonce []byte, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "signed_time", Input: vkeys.SignJWS(vkeys.Key(controlK), TypTime, map[string]any{"server_id": server, "time": vecNow, "nonce": TimeNonce(nonce)}),
			Context: map[string]any{"server_id": fx.Server1, "time_nonce": hex.EncodeToString(tn)}, Expect: expect})
	}
	st("signed-time-valid", fx.Server1, tn, "ok")
	st("signed-time-wrong-nonce", fx.Server1, fx.Bytes("other-nonce", 16), "nonce_mismatch")
	st("signed-time-wrong-server", fx.Server2, tn, "wrong_server")
	return vfile{Format: "routeset", Note: vkeys.Note, Keys: vkeys.Infos(fx.EdgeA, fx.EdgeB, controlK), Cases: cs}
}

func hashed(salt []byte, server string) string { return HashedID(salt, fx.UUID(server)) }

func genFlags() vfile {
	var cs []vcase
	salt := fx.Bytes("flags-salt", 16)
	base := func(f func(map[string]any)) map[string]any {
		c := map[string]any{"generation": 7, "global": "on", "rollout_permille": 0, "salt": vkeys.B64(salt), "allow": []string{}, "deny": []string{}, "iat": vecNow}
		if f != nil {
			f(c)
		}
		return c
	}
	servers := []string{fx.Server1, fx.Server2, "00000000-0000-4000-8000-000000000001", "ffffffff-ffff-4fff-bfff-ffffffffffff"}
	eval := func(name string, claims map[string]any, last int64, expect string) {
		modes := map[string]any{}
		if expect == "ok" {
			for _, s := range servers {
				f, err := ParseFlags(vkeys.JSON(claims))
				if err != nil {
					panic(name + err.Error())
				}
				modes[s] = f.Mode(fx.UUID(s)).String()
			}
		}
		c := vcase{Name: name, Kind: "flags", Input: vkeys.SignJWS(vkeys.Key(controlK), TypFlags, claims), Context: map[string]any{"servers": servers, "last_generation": last}, Expect: expect}
		if expect == "ok" {
			c.Result = map[string]any{"modes": modes, "hashed": map[string]string{fx.Server1: hashed(salt, fx.Server1), fx.Server2: hashed(salt, fx.Server2)}}
		}
		cs = append(cs, c)
	}
	eval("global-on", base(nil), 0, "ok")
	eval("global-off", base(func(c map[string]any) { c["global"] = "off" }), 0, "ok")
	eval("deny-by-hashed-id", base(func(c map[string]any) { c["deny"] = []string{hashed(salt, fx.Server1)} }), 0, "ok")
	eval("deny-beats-allow", base(func(c map[string]any) {
		c["allow"] = []string{hashed(salt, fx.Server1)}
		c["deny"] = []string{hashed(salt, fx.Server1)}
	}), 0, "ok")
	eval("global-off-beats-allow", base(func(c map[string]any) {
		c["global"] = "off"
		c["rollout_permille"] = 1000
		c["allow"] = []string{hashed(salt, fx.Server1)}
	}), 0, "ok")
	eval("rollout-ignored", base(func(c map[string]any) { c["rollout_permille"] = 500 }), 0, "ok")
	eval("raw-server-id-in-deny-ignored", base(func(c map[string]any) {
		c["deny"] = []string{vkeys.B64(append(fx.UUID(fx.Server1), make([]byte, 16)...))}
	}), 0, "ok")
	eval("hash-with-other-salt-ignored", base(func(c map[string]any) { c["deny"] = []string{hashed(fx.Bytes("other-salt", 16), fx.Server1)} }), 0, "ok")
	eval("rollback-lower-generation", base(nil), 8, "rollback")
	eval("rollback-same-generation", base(nil), 7, "rollback")
	eval("newer-generation", base(nil), 6, "ok")
	eval("generation-0", base(func(c map[string]any) { c["generation"] = 0 }), 0, "malformed")
	eval("global-unknown", base(func(c map[string]any) { c["global"] = "partial" }), 0, "malformed")
	eval("permille-1001", base(func(c map[string]any) { c["rollout_permille"] = 1001 }), 0, "malformed")
	eval("permille-negative", base(func(c map[string]any) { c["rollout_permille"] = -1 }), 0, "malformed")
	eval("salt-15-bytes", base(func(c map[string]any) { c["salt"] = vkeys.B64(salt[:15]) }), 0, "malformed")
	eval("allow-not-hash", base(func(c map[string]any) { c["allow"] = []string{fx.Server1} }), 0, "malformed")
	eval("allow-duplicate", base(func(c map[string]any) { c["allow"] = []string{hashed(salt, fx.Server1), hashed(salt, fx.Server1)} }), 0, "malformed")
	eval("mode-claim-not-allowed", base(func(c map[string]any) { c["mode"] = "on" }), 0, "malformed")
	list := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = hashed(salt, fx.UUIDString(fx.Bytes(fmt.Sprintf("s%d", i), 16)))
		}
		return out
	}
	eval("allow-128", base(func(c map[string]any) { c["allow"] = list(128) }), 0, "ok")
	eval("allow-129", base(func(c map[string]any) { c["allow"] = list(129) }), 0, "malformed")
	eval("deny-129", base(func(c map[string]any) { c["deny"] = list(129) }), 0, "malformed")
	full := base(func(c map[string]any) {
		c["generation"] = int64(1)<<53 - 1
		c["iat"] = int64(1)<<53 - 1
		c["allow"] = list(MaxFlagsList)
		c["deny"] = list(2 * MaxFlagsList)[MaxFlagsList:]
	})
	tok := vkeys.SignJWS(vkeys.Key(controlK), TypFlags, full)
	if len(tok) > 16384 {
		panic(fmt.Sprintf("largest flags document is %d bytes", len(tok)))
	}
	cs = append(cs, vcase{Name: "largest-document-fits-cap", Kind: "flags_size", Input: tok, Expect: "ok"})
	cs = append(cs, vcase{Name: "size-16384", Kind: "flags_size", Input: fx.JWS(16384), Expect: "ok"})
	cs = append(cs, vcase{Name: "size-16385", Kind: "flags_size", Input: fx.JWS(16385), Expect: "too_large"})
	return vfile{Format: "flags", Note: vkeys.Note, Keys: vkeys.Infos(controlK), Cases: cs}
}

func genSignedState() vfile {
	var cs []vcase
	n1, n2 := "dGltZS1ub25jZS0wMDAwMDE", "dGltZS1ub25jZS0wMDAwMDI"
	state := func(server, nonce string, f func(map[string]any)) map[string]any {
		c := map[string]any{"server_id": server, "time": vecNow, "nonce": nonce, "device_status": "revoked", "account_status": "active"}
		if f != nil {
			f(c)
		}
		return c
	}
	add := func(name string, input string, nonce, expect string, result any) {
		cs = append(cs, vcase{Name: name, Kind: "signed_state", Input: input, Context: map[string]any{"server_id": fx.Server1, "nonce": nonce}, Expect: expect, Result: result})
	}
	sign := func(c map[string]any) string { return vkeys.SignJWS(vkeys.Key(controlK), TypTime, c) }
	add("revoked-under-right-nonce", sign(state(fx.Server1, n1, nil)), n1, "ok", map[string]any{"has_state": true, "hold": true, "clears": false})
	add("compromised", sign(state(fx.Server1, n1, func(c map[string]any) { c["device_status"] = "compromised" })), n1, "ok", map[string]any{"has_state": true, "hold": true, "clears": false})
	add("suspended-account", sign(state(fx.Server1, n1, func(c map[string]any) { c["device_status"] = "active"; c["account_status"] = "suspended" })), n1, "ok", map[string]any{"has_state": true, "hold": true, "clears": false})
	add("banned-account", sign(state(fx.Server1, n1, func(c map[string]any) { c["device_status"] = "active"; c["account_status"] = "banned" })), n1, "ok", map[string]any{"has_state": true, "hold": true, "clears": false})
	add("active-clears", sign(state(fx.Server1, n1, func(c map[string]any) { c["device_status"] = "active" })), n1, "ok", map[string]any{"has_state": true, "hold": false, "clears": true})
	add("pending-neither", sign(state(fx.Server1, n1, func(c map[string]any) { c["device_status"] = "pending" })), n1, "ok", map[string]any{"has_state": true, "hold": false, "clears": false})
	add("v1-token-live-claim-refused", sign(state(fx.Server1, n1, func(c map[string]any) { c["v1_token_live"] = false })), n1, "malformed", nil)
	add("replayed-against-later-nonce", sign(state(fx.Server1, n1, nil)), n2, "nonce_mismatch", nil)
	add("another-servers-token", sign(state(fx.Server2, n1, nil)), n1, "wrong_server", nil)
	add("missing-nonce", sign(state(fx.Server1, n1, func(c map[string]any) { delete(c, "nonce") })), n1, "malformed", nil)
	add("time-only-has-no-state", sign(map[string]any{"server_id": fx.Server1, "time": vecNow, "nonce": n1}), n1, "ok", map[string]any{"has_state": false, "hold": false, "clears": false})
	add("partial-state-claims", sign(state(fx.Server1, n1, func(c map[string]any) { delete(c, "account_status") })), n1, "malformed", nil)
	add("unknown-device-status", sign(state(fx.Server1, n1, func(c map[string]any) { c["device_status"] = "deleted" })), n1, "malformed", nil)
	add("unknown-account-status", sign(state(fx.Server1, n1, func(c map[string]any) { c["account_status"] = "closed" })), n1, "malformed", nil)
	add("extra-claim", sign(state(fx.Server1, n1, func(c map[string]any) { c["mode"] = "hold" })), n1, "malformed", nil)
	// A status beside the signed token, not inside it: the token carries no
	// state, so the outside claim must not count.
	cs = append(cs, vcase{Name: "status-outside-signed-token", Kind: "signed_state", Input: sign(map[string]any{"server_id": fx.Server1, "time": vecNow, "nonce": n1}),
		Context: map[string]any{"server_id": fx.Server1, "nonce": n1, "unsigned": map[string]any{"device_status": "revoked"}},
		Expect:  "ok", Result: map[string]any{"has_state": false, "hold": false, "clears": false}})
	cs = append(cs, vcase{Name: "signed-by-non-control-key", Kind: "signed_state", Input: vkeys.SignJWS(vkeys.Key(fx.EdgeA), TypTime, state(fx.Server1, n1, nil)),
		Context: map[string]any{"server_id": fx.Server1, "nonce": n1}, Expect: "unknown_key"})
	return vfile{Format: "signed_state", Note: vkeys.Note, Keys: vkeys.Infos(controlK, fx.EdgeA), Cases: cs}
}

func dpop(key string, method, htu string, body []byte, nonce, jti string) string {
	return vkeys.SignJWK(vkeys.Key(key), "dpop+jwt", map[string]any{"jti": jti, "htm": method, "htu": htu, "iat": vecNow, "nonce": nonce, "body_sha256": BodyDigest(body)})
}

func genDeviceCall() vfile {
	var cs []vcase
	bodies := map[pb.DeviceMethod][]byte{
		pb.DeviceMethod_REGISTER_APPS: []byte(`{"apps":[{"local_id":"app-1","host":"127.0.0.1","port":8096}]}`),
		pb.DeviceMethod_DELETE_APPS:   []byte(`{"deleted_ids":["app-2"]}`),
		pb.DeviceMethod_LIST_APPS:     nil,
		pb.DeviceMethod_REPORT_HEALTH: []byte(`{"apps":[{"local_id":"app-1","healthy":true}]}`),
		pb.DeviceMethod_ROTATE_KEY:    []byte(`{"statement":"a.b.c","pop":"d.e.f"}`),
		pb.DeviceMethod_SIGNED_TIME:   []byte(`{"client_nonce":"dGltZS1ub25jZS0wMDAwMDE"}`),
	}
	ctx := func(nonce string) map[string]any {
		return map[string]any{"origin": origin, "server_id": fx.Server1, "server_kid": vkeys.KID(fx.DeviceA), "nonce": nonce}
	}
	call := func(m pb.DeviceMethod, body []byte, proof string) *pb.DeviceCall {
		return &pb.DeviceCall{CallId: 1, IdempotencyKey: fx.Bytes("idem-1", 16), Method: m, Dpop: proof, Body: body}
	}
	add := func(name string, c *pb.DeviceCall, x map[string]any, expect string, result any) {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
		cs = append(cs, vcase{Name: name, Kind: "relayed_call", Input: base64.StdEncoding.EncodeToString(b), Context: x, Expect: expect, Result: result})
	}
	jti := "dGVzdC1qdGktMDAwMDAwMDE"
	for m := pb.DeviceMethod_REGISTER_APPS; m <= pb.DeviceMethod_SIGNED_TIME; m++ {
		r := map[pb.DeviceMethod][2]string{
			pb.DeviceMethod_REGISTER_APPS: {"POST", "/device/v2/apps"}, pb.DeviceMethod_DELETE_APPS: {"POST", "/device/v2/apps/delete"},
			pb.DeviceMethod_LIST_APPS: {"GET", "/device/v2/apps"}, pb.DeviceMethod_REPORT_HEALTH: {"POST", "/device/v2/health"},
			pb.DeviceMethod_ROTATE_KEY: {"POST", "/device/v2/keys/rotate"}, pb.DeviceMethod_SIGNED_TIME: {"POST", "/device/v2/heartbeat"},
		}[m]
		p := dpop(fx.DeviceA, r[0], origin+r[1], bodies[m], vecNonce, jti)
		add("valid-"+m.String(), call(m, bodies[m], p), ctx(vecNonce), "ok", map[string]string{"htm": r[0], "htu": origin + r[1], "body_sha256": BodyDigest(bodies[m])})
	}
	reg := pb.DeviceMethod_REGISTER_APPS
	body := bodies[reg]
	htu := origin + "/device/v2/apps"
	add("first-call-stale-nonce", call(reg, body, dpop(fx.DeviceA, "POST", htu, body, vecNonce, jti)), ctx(vecNonce2), "use_dpop_nonce", map[string]int{"http_status": 401})
	add("retry-with-fresh-nonce", call(reg, body, dpop(fx.DeviceA, "POST", htu, body, vecNonce2, "dGVzdC1qdGktMDAwMDAwMDI")), ctx(vecNonce2), "ok", nil)
	add("proof-for-other-path", call(reg, body, dpop(fx.DeviceA, "POST", origin+"/device/v2/health", body, vecNonce, jti)), ctx(vecNonce), "wrong_htu", nil)
	add("proof-for-other-origin", call(reg, body, dpop(fx.DeviceA, "POST", "https://evil.example/device/v2/apps", body, vecNonce, jti)), ctx(vecNonce), "wrong_htu", nil)
	add("proof-for-other-method", call(reg, body, dpop(fx.DeviceA, "GET", htu, body, vecNonce, jti)), ctx(vecNonce), "wrong_htm", nil)
	add("body-changed-in-relay", call(reg, []byte(`{"apps":[]}`), dpop(fx.DeviceA, "POST", htu, body, vecNonce, jti)), ctx(vecNonce), "body_mismatch", nil)
	add("proof-by-another-device", call(reg, body, dpop(fx.DeviceB, "POST", htu, body, vecNonce, jti)), ctx(vecNonce), "wrong_key", nil)

	key := fx.Bytes("idem-1", 16)
	sum := sha256.Sum256(body)
	dd := func(name string, stored []byte, b []byte, expect Outcome) {
		x := map[string]any{"body": base64.StdEncoding.EncodeToString(b)}
		if stored != nil {
			x["stored_body_sha256"] = hex.EncodeToString(stored)
		}
		cs = append(cs, vcase{Name: name, Kind: "dedupe", Context: x, Expect: string(expect)})
	}
	dd("dedupe-first-call", nil, body, Execute)
	dd("dedupe-duplicate", sum[:], body, Replay)
	dd("dedupe-mismatch", sum[:], []byte(`{"apps":[]}`), Mismatch)
	cs = append(cs, vcase{Name: "dedupe-scope", Kind: "scope", Context: map[string]any{"server_id": fx.Server1, "method": reg.String(), "path": "/device/v2/apps", "key": hex.EncodeToString(key)},
		Expect: "ok", Result: DedupeScope(fx.Server1, reg, "/device/v2/apps", key)})
	return vfile{Format: "device_call", Note: vkeys.Note, Keys: vkeys.Infos(fx.DeviceA, fx.DeviceB), Cases: cs}
}

var _ = ed25519.PublicKeySize
