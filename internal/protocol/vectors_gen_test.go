package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

// Vector keys are derived from public seeds. They are for tests only.
const vectorNote = "TEST ONLY. Every key in this file is derived from a published seed; never use these keys outside tests."

const (
	vecT0      = int64(1790000000)
	vecNow     = int64(1793000000)
	vecNowStr  = "1793000000"
	vecServer1 = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
	vecServer2 = "7c6b5a49-3827-4615-a4b3-c2d1e0f9a8b7"
	vecURL     = "https://api.seawise.io/device/v2/heartbeat"
	vecBody    = `{"client_version":"2.0.0"}`
	vecNonce   = "n1.AAAAAQ.c2VydmVyLW5vbmNl"
	vecJTI     = "dGVzdC1qdGktMDAwMDAwMDE"
	vecRunID   = "cnVuLWlkLTAwMDAwMDAwMDE"
	vecInsID   = "aW5zLWlkLTAwMDAwMDAwMDE"
	vecTimeN   = "dGltZS1ub25jZS0wMDAwMDE"
)

func vecKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("seawise test vector key: " + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func vecPub(name string) ed25519.PublicKey { return vecKey(name).Public().(ed25519.PublicKey) }
func vecX(name string) string              { return b64Encode(vecPub(name)) }
func vecKID(name string) string            { return KeyID(vecPub(name)) }

type vecKeyInfo struct {
	Name        string `json:"name"`
	Seed        string `json:"seed"`
	X           string `json:"x"`
	KID         string `json:"kid"`
	Fingerprint string `json:"fingerprint"`
}

func keyInfos(names ...string) []vecKeyInfo {
	out := make([]vecKeyInfo, 0, len(names))
	for _, n := range names {
		out = append(out, vecKeyInfo{Name: n, Seed: hex.EncodeToString(vecKey(n).Seed()), X: vecX(n), KID: vecKID(n), Fingerprint: Fingerprint(vecPub(n))})
	}
	return out
}

type vecCase struct {
	Name    string          `json:"name"`
	Input   string          `json:"input"`
	Context json.RawMessage `json:"context,omitempty"`
	Expect  string          `json:"expect"`
	Result  json.RawMessage `json:"result,omitempty"`
}

type vecFile struct {
	Format string       `json:"format"`
	Note   string       `json:"note"`
	Keys   []vecKeyInfo `json:"keys"`
	Cases  []vecCase    `json:"cases"`
}

func raw(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	return mustJSON(v)
}

// signRaw signs arbitrary header and payload text, so invalid tokens still
// carry a valid signature and fail for the intended reason.
func signRaw(priv ed25519.PrivateKey, header, payload string) string {
	in := b64Encode([]byte(header)) + "." + b64Encode([]byte(payload))
	return in + "." + b64Encode(ed25519.Sign(priv, []byte(in)))
}

func hs256Token(secret []byte, header, payload string) string {
	in := b64Encode([]byte(header)) + "." + b64Encode([]byte(payload))
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(in))
	return in + "." + b64Encode(m.Sum(nil))
}

func noneToken(header, payload string) string {
	return b64Encode([]byte(header)) + "." + b64Encode([]byte(payload)) + "."
}

func kidHeader(typ, kid string) string {
	return string(mustJSON(signHeader{Typ: typ, Alg: algEdDSA, Kid: kid}))
}

func jwkHeader(typ string, pub ed25519.PublicKey) string {
	j := PublicJWK(pub)
	return string(mustJSON(signHeader{Typ: typ, Alg: algEdDSA, JWK: &j}))
}

func segments(tok string) []string { return strings.Split(tok, ".") }

// Encoding mutations of a valid token.
func withPadding(tok string) string { return tok + "==" }

func withStdAlphabet(tok string) string {
	s := segments(tok)
	s[2] = "+" + s[2][1:]
	return strings.Join(s, ".")
}

func withTrailingBits(tok string) string {
	s := segments(tok)
	sig := s[2]
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alpha, sig[len(sig)-1])
	s[2] = sig[:len(sig)-1] + string(alpha[i|1])
	return strings.Join(s, ".")
}

func withLineBreak(tok string) string {
	s := segments(tok)
	s[1] = s[1][:4] + "\n" + s[1][4:]
	return strings.Join(s, ".")
}

// withHighS replaces S by S + L, which verifies under a lax implementation.
func withHighS(tok string) string {
	s := segments(tok)
	sig, _ := b64Decode(s[2])
	le := make([]byte, 32)
	for i := range 32 {
		le[31-i] = sig[32+i]
	}
	v := new(big.Int).SetBytes(le)
	v.Add(v, groupL)
	be := v.FillBytes(make([]byte, 32))
	for i := range 32 {
		sig[32+i] = be[31-i]
	}
	s[2] = b64Encode(sig)
	return strings.Join(s, ".")
}

func encodingCases(valid string, ctx json.RawMessage) []vecCase {
	return []vecCase{
		{Name: "base64-padding", Input: withPadding(valid), Context: ctx, Expect: "malformed"},
		{Name: "base64-standard-alphabet", Input: withStdAlphabet(valid), Context: ctx, Expect: "malformed"},
		{Name: "base64-nonzero-trailing-bits", Input: withTrailingBits(valid), Context: ctx, Expect: "malformed"},
		{Name: "base64-line-break", Input: withLineBreak(valid), Context: ctx, Expect: "malformed"},
		{Name: "two-segments", Input: strings.Join(segments(valid)[:2], "."), Context: ctx, Expect: "malformed"},
		{Name: "four-segments", Input: valid + ".AAAA", Context: ctx, Expect: "malformed"},
		{Name: "signature-s-not-reduced", Input: withHighS(valid), Context: ctx, Expect: "bad_signature"},
		{Name: "too-large", Input: valid + strings.Repeat("A", maxTokenSize), Context: ctx, Expect: "too_large"},
	}
}

// --- invalid public keys -------------------------------------------------

func encodePoint(x, y *big.Int) []byte {
	be := y.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range 32 {
		out[i] = be[31-i]
	}
	out[31] |= byte(x.Bit(0)) << 7
	return out
}

func pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := fieldP
	x1y2 := new(big.Int).Mul(x1, y2)
	y1x2 := new(big.Int).Mul(y1, x2)
	y1y2 := new(big.Int).Mul(y1, y2)
	x1x2 := new(big.Int).Mul(x1, x2)
	dxy := new(big.Int).Mul(curveD, x1x2)
	dxy.Mul(dxy, y1y2)
	dxy.Mod(dxy, p)
	nx := x1y2.Add(x1y2, y1x2)
	ny := y1y2.Add(y1y2, x1x2)
	dx := new(big.Int).Add(big.NewInt(1), dxy)
	dy := new(big.Int).Sub(big.NewInt(1), dxy)
	dy.Mod(dy, p)
	x3 := nx.Mul(nx, new(big.Int).ModInverse(dx, p))
	y3 := ny.Mul(ny, new(big.Int).ModInverse(dy, p))
	return x3.Mod(x3, p), y3.Mod(y3, p)
}

func scalarMult(k *big.Int, x, y *big.Int) (*big.Int, *big.Int) {
	rx, ry := big.NewInt(0), big.NewInt(1)
	for i := k.BitLen() - 1; i >= 0; i-- {
		rx, ry = pointAdd(rx, ry, rx, ry)
		if k.Bit(i) == 1 {
			rx, ry = pointAdd(rx, ry, x, y)
		}
	}
	return rx, ry
}

// smallOrderEncodings returns the canonical encodings of the eight points
// of order dividing 8, found as L times points decoded from hash outputs
// (seed-derived keys lie in the prime-order subgroup and would give only
// the identity).
func smallOrderEncodings() [][]byte {
	var out [][]byte
	for i := 0; len(out) < 8 && i < 1024; i++ {
		cand := sha256.Sum256([]byte("seawise torsion search " + strconv.Itoa(i)))
		x, y, ok := decodePoint(cand[:])
		if !ok {
			continue
		}
		tx, ty := scalarMult(groupL, x, y)
		enc := encodePoint(tx, ty)
		if !slices.ContainsFunc(out, func(b []byte) bool { return bytes.Equal(b, enc) }) {
			out = append(out, enc)
		}
	}
	slices.SortFunc(out, bytes.Compare)
	return out
}

func notOnCurve() []byte {
	for y := int64(2); ; y++ {
		b := encodePoint(big.NewInt(0), big.NewInt(y))
		if _, _, ok := decodePoint(b); !ok {
			return b
		}
	}
}

// nonCanonicalLargeOrder returns the smallest y below 19 that decodes to a
// point of large order, so y + p is a non-canonical encoding that only the
// canonical check refuses.
func nonCanonicalLargeOrder() int64 {
	for y := int64(2); y < 19; y++ {
		if CheckPublicKey(encodePoint(big.NewInt(0), big.NewInt(y))) == nil {
			return y
		}
	}
	panic("no large-order point with small y")
}

func nonCanonical(add int64) []byte {
	return encodePoint(big.NewInt(0), new(big.Int).Add(fieldP, big.NewInt(add)))
}

// --- keys.json -------------------------------------------------------------

type keyResult struct {
	KID         string `json:"kid"`
	Fingerprint string `json:"fingerprint"`
}

var vecKeyNames = []string{"device-a", "device-b", "device-c", "device-new", "device-old", "root-primary", "root-backup", "root-rogue", "control-1", "control-2", "control-old", "control-rogue", "visitor-1", "edge-1", "release-1"}

func genKeys() vecFile {
	f := vecFile{Format: "keys", Note: vectorNote, Keys: keyInfos(vecKeyNames...)}
	for _, n := range vecKeyNames {
		f.Cases = append(f.Cases, vecCase{Name: "valid-" + n, Input: vecX(n), Expect: "ok", Result: raw(keyResult{KID: vecKID(n), Fingerprint: Fingerprint(vecPub(n))})})
	}
	for i, enc := range smallOrderEncodings() {
		f.Cases = append(f.Cases, vecCase{Name: "small-order-" + string(rune('0'+i)), Input: b64Encode(enc), Expect: "bad_key"})
	}
	f.Cases = append(f.Cases,
		vecCase{Name: "non-canonical-y-equals-p", Input: b64Encode(nonCanonical(0)), Expect: "bad_key"},
		vecCase{Name: "non-canonical-y-equals-p-plus-1", Input: b64Encode(nonCanonical(1)), Expect: "bad_key"},
		vecCase{Name: "non-canonical-large-order-point", Input: b64Encode(nonCanonical(nonCanonicalLargeOrder())), Expect: "bad_key"},
		vecCase{Name: "negative-zero-x", Input: b64Encode(func() []byte { b := encodePoint(big.NewInt(0), big.NewInt(1)); b[31] |= 0x80; return b }()), Expect: "bad_key"},
		vecCase{Name: "not-on-curve", Input: b64Encode(notOnCurve()), Expect: "bad_key"},
		vecCase{Name: "short", Input: b64Encode(vecPub("device-a")[:31]), Expect: "bad_key"},
		vecCase{Name: "long", Input: b64Encode(append(slices.Clone(vecPub("device-a")), 0)), Expect: "bad_key"},
		vecCase{Name: "padded-base64", Input: vecX("device-a") + "=", Expect: "malformed"},
	)
	return f
}

// --- dpop.json -------------------------------------------------------------

type seenJTI struct {
	KID string `json:"kid"`
	JTI string `json:"jti"`
}

type dpopContext struct {
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Body        string    `json:"body"`
	ValidNonces []string  `json:"valid_nonces"`
	Seen        []seenJTI `json:"seen"`
}

type dpopResult struct {
	KID string `json:"kid"`
	JTI string `json:"jti"`
}

func dpopClaims(method, url, body string) DPoPClaims {
	htu, err := CanonicalHTU(url)
	if err != nil {
		panic(err)
	}
	return DPoPClaims{JTI: vecJTI, HTM: method, HTU: htu, IAT: vecNow, Nonce: vecNonce, BodySHA256: BodyDigest([]byte(body))}
}

func genDPoP() vecFile {
	a, b := vecKey("device-a"), vecKey("device-b")
	pubA := vecPub("device-a")
	base := dpopContext{Method: "POST", URL: vecURL, Body: vecBody, ValidNonces: []string{vecNonce}, Seen: []seenJTI{}}
	ctx := func(mut func(*dpopContext)) json.RawMessage {
		c := base
		c.ValidNonces = slices.Clone(base.ValidNonces)
		c.Seen = slices.Clone(base.Seen)
		if mut != nil {
			mut(&c)
		}
		return raw(c)
	}
	sign := func(c DPoPClaims) string {
		t, err := signJWS(a, TypDPoP, true, c)
		if err != nil {
			panic(err)
		}
		return t
	}
	okRes := raw(dpopResult{KID: vecKID("device-a"), JTI: vecJTI})
	hdr := jwkHeader(TypDPoP, pubA)
	claims := dpopClaims("POST", vecURL, vecBody)
	valid := sign(claims)
	cl := func(mut func(*DPoPClaims)) DPoPClaims { c := claims; mut(&c); return c }
	payload := string(mustJSON(claims))

	f := vecFile{Format: "dpop", Note: vectorNote, Keys: keyInfos("device-a", "device-b")}
	add := func(name, input string, c json.RawMessage, expect string) {
		var res json.RawMessage
		if expect == "ok" {
			res = okRes
		}
		f.Cases = append(f.Cases, vecCase{Name: name, Input: input, Context: c, Expect: expect, Result: res})
	}
	add("valid", valid, ctx(nil), "ok")
	add("valid-get-empty-body", sign(dpopClaims("GET", vecURL, "")), ctx(func(c *dpopContext) { c.Method = "GET"; c.Body = "" }), "ok")
	add("valid-request-url-normalised", valid, ctx(func(c *dpopContext) { c.URL = "HTTPS://API.SeaWise.io:443/device/v2/heartbeat?since=5#frag" }), "ok")
	add("valid-iat-not-used-for-freshness", sign(cl(func(c *DPoPClaims) { c.IAT = 0 })), ctx(nil), "ok")
	add("valid-same-jti-other-key", valid, ctx(func(c *dpopContext) { c.Seen = []seenJTI{{KID: vecKID("device-b"), JTI: vecJTI}} }), "ok")
	add("wrong-key", signRaw(b, hdr, payload), ctx(nil), "bad_signature")
	add("wrong-htm", valid, ctx(func(c *dpopContext) { c.Method = "PUT" }), "wrong_htm")
	add("wrong-htm-case", sign(cl(func(c *DPoPClaims) { c.HTM = "post" })), ctx(nil), "wrong_htm")
	add("wrong-htu-path", valid, ctx(func(c *dpopContext) { c.URL = "https://api.seawise.io/device/v2/apps" }), "wrong_htu")
	add("wrong-htu-host", valid, ctx(func(c *dpopContext) { c.URL = "https://evil.example/device/v2/heartbeat" }), "wrong_htu")
	add("wrong-htu-scheme", valid, ctx(func(c *dpopContext) { c.URL = "http://api.seawise.io/device/v2/heartbeat" }), "wrong_htu")
	add("htu-with-query", sign(cl(func(c *DPoPClaims) { c.HTU = vecURL + "?since=5" })), ctx(nil), "wrong_htu")
	add("body-mismatch", valid, ctx(func(c *dpopContext) { c.Body = `{"client_version":"2.0.1"}` }), "body_mismatch")
	add("body-digest-of-empty-on-post", sign(cl(func(c *DPoPClaims) { c.BodySHA256 = BodyDigest(nil) })), ctx(nil), "body_mismatch")
	add("bad-nonce-expired", valid, ctx(func(c *dpopContext) { c.ValidNonces = []string{"n1.AAAAAg.bmV3ZXItbm9uY2U"} }), "bad_nonce")
	add("bad-nonce-syntax", signRaw(a, hdr, strings.Replace(payload, vecNonce, `n1 with space`, 1)), ctx(nil), "bad_nonce")
	add("replayed-jti", valid, ctx(func(c *dpopContext) { c.Seen = []seenJTI{{KID: vecKID("device-a"), JTI: vecJTI}} }), "replayed")
	add("alg-none", noneToken(strings.Replace(hdr, `"EdDSA"`, `"none"`, 1), payload), ctx(nil), "bad_alg")
	add("alg-hs256-public-key-as-secret", hs256Token(pubA, strings.Replace(hdr, `"EdDSA"`, `"HS256"`, 1), payload), ctx(nil), "bad_alg")
	add("alg-ed25519-fully-specified", signRaw(a, strings.Replace(hdr, `"EdDSA"`, `"Ed25519"`, 1), payload), ctx(nil), "bad_alg")
	add("alg-missing", signRaw(a, `{"typ":"dpop+jwt","jwk":`+string(mustJSON(PublicJWK(pubA)))+`}`, payload), ctx(nil), "malformed")
	add("typ-jwt", signRaw(a, strings.Replace(hdr, TypDPoP, "JWT", 1), payload), ctx(nil), "bad_typ")
	add("typ-frp-token", signRaw(a, strings.Replace(hdr, TypDPoP, TypFRP, 1), payload), ctx(nil), "bad_typ")
	add("header-kid-not-jwk", signRaw(a, kidHeader(TypDPoP, vecKID("device-a")), payload), ctx(nil), "malformed")
	add("header-crit", signRaw(a, strings.TrimSuffix(hdr, "}")+`,"crit":["exp"]}`, payload), ctx(nil), "malformed")
	add("header-jku", signRaw(a, strings.TrimSuffix(hdr, "}")+`,"jku":"https://evil.example/jwks"}`, payload), ctx(nil), "malformed")
	add("jwk-with-private-d", signRaw(a, strings.Replace(hdr, `"x":`, `"d":"`+b64Encode(a.Seed())+`","x":`, 1), payload), ctx(nil), "bad_key")
	add("jwk-wrong-curve", signRaw(a, strings.Replace(hdr, `"Ed25519"`, `"X25519"`, 1), payload), ctx(nil), "bad_key")
	add("jwk-small-order", signRaw(a, strings.Replace(hdr, vecX("device-a"), b64Encode(encodePoint(big.NewInt(0), big.NewInt(1))), 1), payload), ctx(nil), "bad_key")
	add("jwk-non-canonical", signRaw(a, strings.Replace(hdr, vecX("device-a"), b64Encode(nonCanonical(1)), 1), payload), ctx(nil), "bad_key")
	add("claim-duplicate", signRaw(a, hdr, strings.Replace(payload, `"htm":"POST"`, `"htm":"GET","htm":"POST"`, 1)), ctx(nil), "malformed")
	add("claim-case-variant", signRaw(a, hdr, strings.Replace(payload, `"htm":"POST"`, `"htm":"POST","HTM":"GET"`, 1)), ctx(nil), "malformed")
	add("claim-unknown", signRaw(a, hdr, strings.TrimSuffix(payload, "}")+`,"ath":"x"}`), ctx(nil), "malformed")
	add("claim-missing-body-digest", signRaw(a, hdr, strings.Replace(payload, `,"body_sha256":"`+claims.BodySHA256+`"`, "", 1)), ctx(nil), "malformed")
	add("claim-null", signRaw(a, hdr, strings.Replace(payload, `"nonce":"`+vecNonce+`"`, `"nonce":null`, 1)), ctx(nil), "malformed")
	add("claim-iat-fraction", signRaw(a, hdr, strings.Replace(payload, `"iat":`+vecNowStr, `"iat":`+vecNowStr+`.5`, 1)), ctx(nil), "malformed")
	add("claim-iat-negative", signRaw(a, hdr, strings.Replace(payload, `"iat":`+vecNowStr, `"iat":-1`, 1)), ctx(nil), "malformed")
	add("claim-jti-too-short", signRaw(a, hdr, strings.Replace(payload, vecJTI, "c2hvcnQ", 1)), ctx(nil), "malformed")
	add("payload-invalid-utf8", signRaw(a, hdr, strings.Replace(payload, "/device", "/dev\xffice", 1)), ctx(nil), "malformed")
	add("payload-trailing-data", signRaw(a, hdr, payload+"{}"), ctx(nil), "malformed")
	add("payload-not-object", signRaw(a, hdr, `["jti"]`), ctx(nil), "malformed")
	for _, c := range encodingCases(valid, ctx(nil)) {
		f.Cases = append(f.Cases, c)
	}
	return f
}

// --- frp_token.json --------------------------------------------------------

type registryJSON struct {
	ServerID  string `json:"server_id"`
	X         string `json:"x"`
	Status    string `json:"status"`
	ValidFrom int64  `json:"valid_from"`
}

type frpContext struct {
	Now           int64          `json:"now"`
	LoginServerID string         `json:"login_server_id"`
	Registry      []registryJSON `json:"registry"`
}

func vecRegistry() []registryJSON {
	return []registryJSON{
		{ServerID: vecServer1, X: vecX("device-a"), Status: StatusActive, ValidFrom: vecT0},
		{ServerID: vecServer2, X: vecX("device-b"), Status: StatusActive, ValidFrom: vecT0},
		{ServerID: vecServer1, X: vecX("device-old"), Status: StatusRevoked, ValidFrom: vecT0 - 86400},
	}
}

func genFRP() vecFile {
	a, b := vecKey("device-a"), vecKey("device-b")
	ctxFor := func(now int64, login string) json.RawMessage {
		return raw(frpContext{Now: now, LoginServerID: login, Registry: vecRegistry()})
	}
	ctx := ctxFor(vecNow, vecServer1)
	mint := func(k ed25519.PrivateKey, server string, iat int64) string {
		t, err := NewFRPToken(k, server, vecRunID, iat)
		if err != nil {
			panic(err)
		}
		return t
	}
	valid := mint(a, vecServer1, vecNow-3600)
	hdr := kidHeader(TypFRP, vecKID("device-a"))
	claims := FRPClaims{ServerID: vecServer1, KeyID: vecKID("device-a"), IAT: vecNow - 3600, RunID: vecRunID}
	payload := string(mustJSON(claims))
	res := func(iat int64) json.RawMessage {
		c := claims
		c.IAT = iat
		return raw(c)
	}

	f := vecFile{Format: "frp_token", Note: vectorNote, Keys: keyInfos("device-a", "device-b", "device-c", "device-old")}
	f.Cases = []vecCase{
		{Name: "valid", Input: valid, Context: ctx, Expect: "ok", Result: res(vecNow - 3600)},
		{Name: "valid-last-second", Input: mint(a, vecServer1, vecNow-FRPTokenLifetime), Context: ctx, Expect: "ok", Result: res(vecNow - FRPTokenLifetime)},
		{Name: "valid-future-within-leeway", Input: mint(a, vecServer1, vecNow+leewaySec), Context: ctx, Expect: "ok", Result: res(vecNow + leewaySec)},
		{Name: "valid-at-key-registration-leeway", Input: mint(a, vecServer1, vecT0-leewaySec), Context: ctxFor(vecT0+10, vecServer1), Expect: "ok", Result: res(vecT0 - leewaySec)},
		{Name: "expired", Input: mint(a, vecServer1, vecNow-FRPTokenLifetime-1), Context: ctx, Expect: "expired"},
		{Name: "not-yet-valid", Input: mint(a, vecServer1, vecNow+leewaySec+1), Context: ctx, Expect: "not_yet_valid"},
		{Name: "before-key-valid", Input: mint(a, vecServer1, vecT0-leewaySec-1), Context: ctxFor(vecT0+10, vecServer1), Expect: "before_key_valid"},
		{Name: "wrong-key", Input: signRaw(b, hdr, payload), Context: ctx, Expect: "bad_signature"},
		{Name: "unknown-key", Input: mint(vecKey("device-c"), vecServer1, vecNow), Context: ctx, Expect: "unknown_key"},
		{Name: "revoked-key", Input: mint(vecKey("device-old"), vecServer1, vecNow), Context: ctx, Expect: "key_revoked"},
		{Name: "wrong-server-login", Input: valid, Context: ctxFor(vecNow, vecServer2), Expect: "wrong_server"},
		{Name: "wrong-server-claim", Input: mint(a, vecServer2, vecNow), Context: ctxFor(vecNow, vecServer2), Expect: "wrong_server"},
		{Name: "key-id-differs-from-kid", Input: signRaw(a, hdr, strings.Replace(payload, vecKID("device-a"), vecKID("device-b"), 1)), Context: ctx, Expect: "malformed"},
		{Name: "server-id-not-canonical", Input: signRaw(a, hdr, strings.Replace(payload, vecServer1, strings.ToUpper(vecServer1), 1)), Context: ctx, Expect: "malformed"},
		{Name: "run-id-invalid", Input: signRaw(a, hdr, strings.Replace(payload, vecRunID, "run id", 1)), Context: ctx, Expect: "malformed"},
		{Name: "claim-duplicate", Input: signRaw(a, hdr, strings.Replace(payload, `"server_id":"`+vecServer1+`"`, `"server_id":"`+vecServer2+`","server_id":"`+vecServer1+`"`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "claim-unknown-exp", Input: signRaw(a, hdr, strings.TrimSuffix(payload, "}")+`,"exp":1}`), Context: ctx, Expect: "malformed"},
		{Name: "alg-none", Input: noneToken(strings.Replace(hdr, `"EdDSA"`, `"none"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "alg-hs256-public-key-as-secret", Input: hs256Token(vecPub("device-a"), strings.Replace(hdr, `"EdDSA"`, `"HS256"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "typ-dpop", Input: signRaw(a, kidHeader(TypDPoP, vecKID("device-a")), payload), Context: ctx, Expect: "bad_typ"},
		{Name: "typ-missing", Input: signRaw(a, `{"alg":"EdDSA","kid":"`+vecKID("device-a")+`"}`, payload), Context: ctx, Expect: "bad_typ"},
		{Name: "header-jwk-not-kid", Input: signRaw(a, jwkHeader(TypFRP, vecPub("device-a")), payload), Context: ctx, Expect: "malformed"},
	}
	f.Cases = append(f.Cases, encodingCases(valid, ctx)...)
	return f
}

// --- rotation.json ---------------------------------------------------------

type rotationContext struct {
	ServerID string         `json:"server_id"`
	Registry []registryJSON `json:"registry"`
}

type rotationResult struct {
	OldKID string `json:"old_kid"`
	NewKID string `json:"new_kid"`
}

func genRotation() vecFile {
	a, nk := vecKey("device-a"), vecKey("device-new")
	ctx := raw(rotationContext{ServerID: vecServer1, Registry: vecRegistry()})
	enc := func(r Rotation) string { return string(mustJSON(r)) }
	rot := func(old, nw ed25519.PrivateKey, server string) Rotation {
		r, err := NewRotation(old, nw, server, vecNow)
		if err != nil {
			panic(err)
		}
		return r
	}
	valid := rot(a, nk, vecServer1)
	claims := RotationClaims{ServerID: vecServer1, OldKID: vecKID("device-a"), NewJWK: mustJSON(PublicJWK(vecPub("device-new"))), IAT: vecNow}
	payload := string(mustJSON(claims))
	stHdr := kidHeader(TypRotate, vecKID("device-a"))
	popHdr := kidHeader(TypRotatePoP, vecKID("device-new"))
	pair := func(st, pop string) string { return enc(Rotation{Statement: st, PoP: pop}) }
	smallJWK := strings.Replace(payload, vecX("device-new"), b64Encode(encodePoint(big.NewInt(0), big.NewInt(1))), 1)

	f := vecFile{Format: "rotation", Note: vectorNote, Keys: keyInfos("device-a", "device-b", "device-c", "device-new", "device-old")}
	f.Cases = []vecCase{
		{Name: "valid", Input: enc(valid), Context: ctx, Expect: "ok", Result: raw(rotationResult{OldKID: vecKID("device-a"), NewKID: vecKID("device-new")})},
		{Name: "statement-wrong-key", Input: pair(signRaw(vecKey("device-b"), stHdr, payload), valid.PoP), Context: ctx, Expect: "bad_signature"},
		{Name: "pop-wrong-key", Input: pair(valid.Statement, signRaw(vecKey("device-c"), popHdr, payload)), Context: ctx, Expect: "bad_signature"},
		{Name: "pop-signed-by-old-key", Input: pair(valid.Statement, signRaw(a, kidHeader(TypRotatePoP, vecKID("device-a")), payload)), Context: ctx, Expect: "malformed"},
		{Name: "payloads-differ-new-key", Input: pair(valid.Statement, rot(a, vecKey("device-c"), vecServer1).PoP), Context: ctx, Expect: "malformed"},
		{Name: "payloads-differ-iat", Input: pair(valid.Statement, signRaw(nk, popHdr, strings.Replace(payload, `"iat":`+vecNowStr, `"iat":1`, 1))), Context: ctx, Expect: "malformed"},
		{Name: "old-key-revoked", Input: enc(rot(vecKey("device-old"), nk, vecServer1)), Context: ctx, Expect: "key_revoked"},
		{Name: "old-key-unknown", Input: enc(rot(vecKey("device-c"), nk, vecServer1)), Context: ctx, Expect: "unknown_key"},
		{Name: "wrong-server-claim", Input: enc(rot(a, nk, vecServer2)), Context: ctx, Expect: "wrong_server"},
		{Name: "wrong-server-requester", Input: enc(valid), Context: raw(rotationContext{ServerID: vecServer2, Registry: vecRegistry()}), Expect: "wrong_server"},
		{Name: "new-key-equals-old", Input: pair(signRaw(a, stHdr, strings.Replace(payload, vecX("device-new"), vecX("device-a"), 1)), signRaw(a, kidHeader(TypRotatePoP, vecKID("device-a")), strings.Replace(payload, vecX("device-new"), vecX("device-a"), 1))), Context: ctx, Expect: "bad_key"},
		{Name: "new-key-small-order", Input: pair(signRaw(a, stHdr, smallJWK), signRaw(nk, popHdr, smallJWK)), Context: ctx, Expect: "bad_key"},
		{Name: "new-jwk-private-d", Input: pair(signRaw(a, stHdr, strings.Replace(payload, `"x":`, `"d":"`+b64Encode(nk.Seed())+`","x":`, 1)), signRaw(nk, popHdr, strings.Replace(payload, `"x":`, `"d":"`+b64Encode(nk.Seed())+`","x":`, 1))), Context: ctx, Expect: "bad_key"},
		{Name: "typ-swapped", Input: pair(valid.PoP, valid.Statement), Context: ctx, Expect: "bad_typ"},
		{Name: "statement-alg-none", Input: pair(noneToken(strings.Replace(stHdr, `"EdDSA"`, `"none"`, 1), payload), valid.PoP), Context: ctx, Expect: "bad_alg"},
		{Name: "object-unknown-member", Input: strings.TrimSuffix(enc(valid), "}") + `,"note":"x"}`, Context: ctx, Expect: "malformed"},
		{Name: "object-missing-pop", Input: `{"statement":"` + valid.Statement + `"}`, Context: ctx, Expect: "malformed"},
		{Name: "object-not-json", Input: valid.Statement, Context: ctx, Expect: "malformed"},
	}
	return f
}

// --- keyset.json -----------------------------------------------------------

type keysetContext struct {
	Roots       []string `json:"roots"`
	LastVersion int64    `json:"last_version"`
	LastDigest  string   `json:"last_digest,omitempty"`
}

type keysetResult struct {
	Version int64    `json:"version"`
	KIDs    []string `json:"kids"`
	Digest  string   `json:"digest"`
}

func vecEntry(name, role, status, edge string) KeySetEntry {
	return KeySetEntry{KID: vecKID(name), Role: role, X: vecX(name), Status: status, Name: edge}
}

func vecKeySetEntries() []KeySetEntry {
	return []KeySetEntry{
		vecEntry("control-1", RoleControl, StatusActive, ""),
		vecEntry("control-2", RoleControl, StatusNext, ""),
		vecEntry("control-old", RoleControl, StatusRevoked, ""),
		vecEntry("visitor-1", RoleVisitor, StatusActive, ""),
		vecEntry("edge-1", RoleEdge, StatusActive, "edge-fsn1-1"),
		vecEntry("release-1", RoleRelease, StatusActive, ""),
	}
}

func vecKeySet(version int64) string {
	t, err := NewKeySet(vecKey("root-primary"), version, vecT0, vecKeySetEntries())
	if err != nil {
		panic(err)
	}
	return t
}

func vecRoots() []string { return []string{vecX("root-primary"), vecX("root-backup")} }

func genKeySet() vecFile {
	primary := vecKey("root-primary")
	ctxV := func(last int64, digest string) json.RawMessage {
		return raw(keysetContext{Roots: vecRoots(), LastVersion: last, LastDigest: digest})
	}
	ctx := ctxV(4, "")
	valid := vecKeySet(5)
	hdr := kidHeader(TypKeySet, vecKID("root-primary"))
	payloadOf := func(entries []KeySetEntry, version int64) string {
		return string(mustJSON(keySetSign{Version: version, IAT: vecT0, Keys: entries}))
	}
	payload := payloadOf(vecKeySetEntries(), 5)
	digest := sha256.Sum256([]byte(payload))
	kids := []string{}
	for _, e := range vecKeySetEntries() {
		kids = append(kids, e.KID)
	}
	okRes := raw(keysetResult{Version: 5, KIDs: kids, Digest: b64Encode(digest[:])})
	mut := func(fn func([]KeySetEntry) []KeySetEntry) string {
		return signRaw(primary, hdr, payloadOf(fn(vecKeySetEntries()), 5))
	}
	backup, _ := NewKeySet(vecKey("root-backup"), 5, vecT0, vecKeySetEntries())
	rogue, _ := NewKeySet(vecKey("root-rogue"), 5, vecT0, vecKeySetEntries())
	changed := mut(func(e []KeySetEntry) []KeySetEntry { return e[:5] })

	f := vecFile{Format: "keyset", Note: vectorNote, Keys: keyInfos("root-primary", "root-backup", "root-rogue", "control-1", "control-2", "control-old", "visitor-1", "edge-1", "release-1")}
	f.Cases = []vecCase{
		{Name: "valid-primary-root", Input: valid, Context: ctx, Expect: "ok", Result: okRes},
		{Name: "valid-backup-root", Input: backup, Context: ctx, Expect: "ok", Result: okRes},
		{Name: "valid-first-load", Input: valid, Context: ctxV(0, ""), Expect: "ok", Result: okRes},
		{Name: "valid-same-version-same-payload", Input: valid, Context: ctxV(5, b64Encode(digest[:])), Expect: "ok", Result: okRes},
		{Name: "rollback-older-version", Input: valid, Context: ctxV(6, ""), Expect: "rollback"},
		{Name: "rollback-same-version-other-payload", Input: changed, Context: ctxV(5, b64Encode(digest[:])), Expect: "rollback"},
		{Name: "unknown-root", Input: rogue, Context: ctx, Expect: "unknown_key"},
		{Name: "wrong-key", Input: signRaw(vecKey("root-rogue"), hdr, payload), Context: ctx, Expect: "bad_signature"},
		{Name: "alg-none", Input: noneToken(strings.Replace(hdr, `"EdDSA"`, `"none"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "alg-hs256-public-key-as-secret", Input: hs256Token(vecPub("root-primary"), strings.Replace(hdr, `"EdDSA"`, `"HS256"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "typ-instruction", Input: signRaw(primary, kidHeader(TypInstr, vecKID("root-primary")), payload), Context: ctx, Expect: "bad_typ"},
		{Name: "entry-kid-mismatch", Input: mut(func(e []KeySetEntry) []KeySetEntry { e[0].KID = vecKID("control-2"); return e }), Context: ctx, Expect: "malformed"},
		{Name: "entry-duplicate-kid", Input: mut(func(e []KeySetEntry) []KeySetEntry { return append(e, e[0]) }), Context: ctx, Expect: "malformed"},
		{Name: "entry-unknown-role", Input: mut(func(e []KeySetEntry) []KeySetEntry { e[0].Role = "admin"; return e }), Context: ctx, Expect: "malformed"},
		{Name: "entry-unknown-status", Input: mut(func(e []KeySetEntry) []KeySetEntry { e[0].Status = "retired"; return e }), Context: ctx, Expect: "malformed"},
		{Name: "entry-edge-without-name", Input: mut(func(e []KeySetEntry) []KeySetEntry { e[4].Name = ""; return e }), Context: ctx, Expect: "malformed"},
		{Name: "entry-name-on-control", Input: mut(func(e []KeySetEntry) []KeySetEntry { e[0].Name = "edge-x"; return e }), Context: ctx, Expect: "malformed"},
		{Name: "entry-edge-name-syntax", Input: mut(func(e []KeySetEntry) []KeySetEntry { e[4].Name = "Edge_1."; return e }), Context: ctx, Expect: "malformed"},
		{Name: "entry-small-order-key", Input: mut(func(e []KeySetEntry) []KeySetEntry {
			x := b64Encode(encodePoint(big.NewInt(0), big.NewInt(1)))
			e[0].X = x
			e[0].KID = KeyID(ed25519.PublicKey(encodePoint(big.NewInt(0), big.NewInt(1))))
			return e
		}), Context: ctx, Expect: "bad_key"},
		{Name: "entry-unknown-member", Input: signRaw(primary, hdr, strings.Replace(payload, `"status":"active"`, `"status":"active","use":"sig"`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "no-keys", Input: mut(func([]KeySetEntry) []KeySetEntry { return []KeySetEntry{} }), Context: ctx, Expect: "malformed"},
		{Name: "version-zero", Input: signRaw(primary, hdr, payloadOf(vecKeySetEntries(), 0)), Context: ctxV(0, ""), Expect: "malformed"},
		{Name: "too-large", Input: valid + strings.Repeat("A", maxKeySetSize), Context: ctx, Expect: "too_large"},
	}
	for _, c := range encodingCases(valid, ctx) {
		if c.Name != "too-large" {
			f.Cases = append(f.Cases, c)
		}
	}
	return f
}

// --- instruction.json ------------------------------------------------------

type instrContext struct {
	ServerID string   `json:"server_id"`
	Now      int64    `json:"now"`
	Roots    []string `json:"roots"`
	KeySet   string   `json:"keyset"`
	Executed []string `json:"executed"`
}

func genInstruction() vecFile {
	c1 := vecKey("control-1")
	ctxFor := func(server string, now int64, executed []string) json.RawMessage {
		return raw(instrContext{ServerID: server, Now: now, Roots: vecRoots(), KeySet: vecKeySet(5), Executed: executed})
	}
	ctx := ctxFor(vecServer1, vecNow, []string{})
	base := Instruction{InsID: vecInsID, ServerID: vecServer1, Op: OpDisableApp, Args: InstructionArgs{LocalID: "9f8e7d6c5b4a39281706f5e4d3c2b1a0"}, IAT: vecNow - 60, EXP: vecNow + 3000}
	with := func(fn func(*Instruction)) Instruction { in := base; fn(&in); return in }
	sign := func(k ed25519.PrivateKey, in Instruction) string {
		t, err := signJWS(k, TypInstr, false, in)
		if err != nil {
			panic(err)
		}
		return t
	}
	valid := sign(c1, base)
	hdr := kidHeader(TypInstr, vecKID("control-1"))
	payload := string(mustJSON(base))
	ok := func(name string, in Instruction) vecCase {
		t, err := NewInstruction(c1, in)
		if err != nil {
			panic(err)
		}
		return vecCase{Name: name, Input: t, Context: ctx, Expect: "ok", Result: raw(in)}
	}

	f := vecFile{Format: "instruction", Note: vectorNote, Keys: keyInfos("root-primary", "root-backup", "control-1", "control-2", "control-old", "control-rogue", "visitor-1")}
	f.Cases = []vecCase{
		ok("valid-disable-app", base),
		ok("valid-delete-app", with(func(in *Instruction) { in.Op = OpDeleteApp })),
		ok("valid-unpair", with(func(in *Instruction) { in.Op = OpUnpair; in.Args = InstructionArgs{} })),
		ok("valid-set-visitor-enforcement", with(func(in *Instruction) { in.Op = OpSetVisitorEnforcement; in.Args = InstructionArgs{Mode: "enforce"} })),
		{Name: "valid-announced-next-key", Input: sign(vecKey("control-2"), base), Context: ctx, Expect: "ok", Result: raw(base)},
		{Name: "valid-expiry-within-leeway", Input: sign(c1, with(func(in *Instruction) { in.IAT = vecNow - 900; in.EXP = vecNow - leewaySec })), Context: ctx, Expect: "ok", Result: raw(with(func(in *Instruction) { in.IAT = vecNow - 900; in.EXP = vecNow - leewaySec }))},
		{Name: "expired", Input: sign(c1, with(func(in *Instruction) { in.IAT = vecNow - 900; in.EXP = vecNow - leewaySec - 1 })), Context: ctx, Expect: "expired"},
		{Name: "not-yet-valid", Input: sign(c1, with(func(in *Instruction) { in.IAT = vecNow + leewaySec + 1; in.EXP = vecNow + 3000 })), Context: ctx, Expect: "not_yet_valid"},
		{Name: "replayed", Input: valid, Context: ctxFor(vecServer1, vecNow, []string{vecInsID}), Expect: "replayed"},
		{Name: "wrong-server", Input: valid, Context: ctxFor(vecServer2, vecNow, []string{}), Expect: "wrong_server"},
		{Name: "revoked-key", Input: sign(vecKey("control-old"), base), Context: ctx, Expect: "key_revoked"},
		{Name: "wrong-key-role-visitor", Input: sign(vecKey("visitor-1"), base), Context: ctx, Expect: "wrong_key_role"},
		{Name: "unknown-key", Input: sign(vecKey("control-rogue"), base), Context: ctx, Expect: "unknown_key"},
		{Name: "wrong-key", Input: signRaw(vecKey("control-2"), hdr, payload), Context: ctx, Expect: "bad_signature"},
		{Name: "root-key-not-control", Input: sign(vecKey("root-primary"), base), Context: ctx, Expect: "unknown_key"},
		{Name: "lifetime-too-long", Input: sign(c1, with(func(in *Instruction) { in.EXP = in.IAT + maxInstructionLife + 1 })), Context: ctx, Expect: "malformed"},
		{Name: "exp-before-iat", Input: sign(c1, with(func(in *Instruction) { in.EXP = in.IAT })), Context: ctx, Expect: "malformed"},
		{Name: "unknown-op", Input: sign(c1, with(func(in *Instruction) { in.Op = "run_command" })), Context: ctx, Expect: "malformed"},
		{Name: "unpair-with-args", Input: sign(c1, with(func(in *Instruction) { in.Op = OpUnpair })), Context: ctx, Expect: "malformed"},
		{Name: "bad-enforcement-mode", Input: sign(c1, with(func(in *Instruction) { in.Op = OpSetVisitorEnforcement; in.Args = InstructionArgs{Mode: "off"} })), Context: ctx, Expect: "malformed"},
		{Name: "args-unknown-member", Input: signRaw(c1, hdr, strings.Replace(payload, `"args":{`, `"args":{"all":true,`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "claim-duplicate-op", Input: signRaw(c1, hdr, strings.Replace(payload, `"op":"disable_app"`, `"op":"unpair","op":"disable_app"`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "alg-none", Input: noneToken(strings.Replace(hdr, `"EdDSA"`, `"none"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "alg-hs256-public-key-as-secret", Input: hs256Token(vecPub("control-1"), strings.Replace(hdr, `"EdDSA"`, `"HS256"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "typ-signed-time", Input: signRaw(c1, kidHeader(TypTime, vecKID("control-1")), payload), Context: ctx, Expect: "bad_typ"},
	}
	f.Cases = append(f.Cases, encodingCases(valid, ctx)...)
	return f
}

// --- signed_time.json ------------------------------------------------------

type timeContext struct {
	ServerID string   `json:"server_id"`
	Nonce    string   `json:"nonce"`
	Roots    []string `json:"roots"`
	KeySet   string   `json:"keyset"`
}

func genSignedTime() vecFile {
	c1 := vecKey("control-1")
	ctxFor := func(server, nonce string) json.RawMessage {
		return raw(timeContext{ServerID: server, Nonce: nonce, Roots: vecRoots(), KeySet: vecKeySet(5)})
	}
	ctx := ctxFor(vecServer1, vecTimeN)
	base := SignedTime{ServerID: vecServer1, Time: vecNow, Nonce: vecTimeN}
	sign := func(k ed25519.PrivateKey, st SignedTime) string {
		t, err := signJWS(k, TypTime, false, st)
		if err != nil {
			panic(err)
		}
		return t
	}
	valid := sign(c1, base)
	hdr := kidHeader(TypTime, vecKID("control-1"))
	payload := string(mustJSON(base))

	f := vecFile{Format: "signed_time", Note: vectorNote, Keys: keyInfos("root-primary", "root-backup", "control-1", "control-2", "control-old", "control-rogue", "edge-1")}
	f.Cases = []vecCase{
		{Name: "valid", Input: valid, Context: ctx, Expect: "ok", Result: raw(base)},
		{Name: "valid-announced-next-key", Input: sign(vecKey("control-2"), base), Context: ctx, Expect: "ok", Result: raw(base)},
		{Name: "valid-epoch-zero", Input: sign(c1, SignedTime{ServerID: vecServer1, Time: 0, Nonce: vecTimeN}), Context: ctx, Expect: "ok", Result: raw(SignedTime{ServerID: vecServer1, Time: 0, Nonce: vecTimeN})},
		{Name: "nonce-mismatch", Input: valid, Context: ctxFor(vecServer1, "b3RoZXItbm9uY2UtMDAwMDAy"), Expect: "nonce_mismatch"},
		{Name: "wrong-server", Input: valid, Context: ctxFor(vecServer2, vecTimeN), Expect: "wrong_server"},
		{Name: "edge-key-not-control", Input: sign(vecKey("edge-1"), base), Context: ctx, Expect: "wrong_key_role"},
		{Name: "revoked-key", Input: sign(vecKey("control-old"), base), Context: ctx, Expect: "key_revoked"},
		{Name: "unknown-key", Input: sign(vecKey("control-rogue"), base), Context: ctx, Expect: "unknown_key"},
		{Name: "wrong-key", Input: signRaw(vecKey("control-2"), hdr, payload), Context: ctx, Expect: "bad_signature"},
		{Name: "time-fraction", Input: signRaw(c1, hdr, strings.Replace(payload, `"time":`+vecNowStr, `"time":`+vecNowStr+`.25`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "time-negative", Input: signRaw(c1, hdr, strings.Replace(payload, `"time":`+vecNowStr, `"time":-5`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "time-beyond-2-53", Input: signRaw(c1, hdr, strings.Replace(payload, `"time":`+vecNowStr, `"time":9007199254740992`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "time-string", Input: signRaw(c1, hdr, strings.Replace(payload, `"time":`+vecNowStr, `"time":"`+vecNowStr+`"`, 1)), Context: ctx, Expect: "malformed"},
		{Name: "alg-none", Input: noneToken(strings.Replace(hdr, `"EdDSA"`, `"none"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "alg-hs256-public-key-as-secret", Input: hs256Token(vecPub("control-1"), strings.Replace(hdr, `"EdDSA"`, `"HS256"`, 1), payload), Context: ctx, Expect: "bad_alg"},
		{Name: "typ-instruction", Input: signRaw(c1, kidHeader(TypInstr, vecKID("control-1")), payload), Context: ctx, Expect: "bad_typ"},
	}
	f.Cases = append(f.Cases, encodingCases(valid, ctx)...)
	return f
}

func generateVectors() map[string]vecFile {
	return map[string]vecFile{
		"keys.json":        genKeys(),
		"dpop.json":        genDPoP(),
		"frp_token.json":   genFRP(),
		"rotation.json":    genRotation(),
		"keyset.json":      genKeySet(),
		"instruction.json": genInstruction(),
		"signed_time.json": genSignedTime(),
	}
}
