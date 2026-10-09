package protocol

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
)

func TestCanonicalHTU(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://api.seawise.io/device/v2/heartbeat", "https://api.seawise.io/device/v2/heartbeat"},
		{"HTTPS://API.SeaWise.IO:443/x?y=1#z", "https://api.seawise.io/x"},
		{"https://api.seawise.io", "https://api.seawise.io/"},
		{"https://api.seawise.io:8443/a/b", "https://api.seawise.io:8443/a/b"},
		{"http://localhost:80/a", "http://localhost/a"},
		{"http://localhost:8080/a", "http://localhost:8080/a"},
		{"https://[::1]:443/a", "https://[::1]/a"},
		{"https://[::1]:8443/a", "https://[::1]:8443/a"},
		{"https://api.seawise.io/a%2Fb", "https://api.seawise.io/a%2Fb"},
	} {
		got, err := CanonicalHTU(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("CanonicalHTU(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "/relative", "ftp://x/", "https://user:pw@api.seawise.io/", "mailto:a@b", "https:///path", "https://%zz/"} {
		if _, err := CanonicalHTU(bad); CodeOf(err) != CodeMalformed {
			t.Errorf("CanonicalHTU(%q) = %v, want malformed", bad, err)
		}
	}
}

func genKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestDPoPRoundTrip(t *testing.T) {
	k := genKey(t)
	jti := b64Encode(make([]byte, 16))
	tok, err := NewDPoP(k, "POST", "https://API.seawise.io/x?q=1", []byte("body"), "nonce-1", jti, 1)
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	claim := func(kid, jti string) bool {
		if used[kid+jti] {
			return false
		}
		used[kid+jti] = true
		return true
	}
	ok := func(n string) bool { return n == "nonce-1" }
	req := DPoPRequest{Method: "POST", URL: "https://api.seawise.io/x", Body: []byte("body")}
	r, err := VerifyDPoP(tok, req, ok, claim)
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyID != KeyID(k.Public().(ed25519.PublicKey)) {
		t.Fatal("key id mismatch")
	}
	if _, err := VerifyDPoP(tok, req, ok, claim); CodeOf(err) != CodeReplayed {
		t.Fatalf("second use: %v, want replayed", err)
	}
}

func TestRejectedProofDoesNotConsumeJTI(t *testing.T) {
	k := genKey(t)
	jti := b64Encode(make([]byte, 16))
	tok, _ := NewDPoP(k, "POST", "https://api.seawise.io/x", nil, "n", jti, 1)
	calls := 0
	claim := func(string, string) bool { calls++; return true }
	_, err := VerifyDPoP(tok, DPoPRequest{Method: "GET", URL: "https://api.seawise.io/x"}, func(string) bool { return true }, claim)
	if CodeOf(err) != CodeWrongHTM || calls != 0 {
		t.Fatalf("err %v, claim calls %d", err, calls)
	}
}

func TestNewDPoPRefusesBadInput(t *testing.T) {
	k := genKey(t)
	jti := b64Encode(make([]byte, 16))
	if _, err := NewDPoP(k, "POST", "https://api.seawise.io/", nil, "bad nonce", jti, 1); err == nil {
		t.Error("accepted a nonce with a space")
	}
	if _, err := NewDPoP(k, "POST", "https://api.seawise.io/", nil, "n", "short", 1); err == nil {
		t.Error("accepted a short jti")
	}
	if _, err := NewDPoP(k, "POST", "not a url", nil, "n", jti, 1); err == nil {
		t.Error("accepted a relative url")
	}
}

func TestSignerMustBeEd25519(t *testing.T) {
	if _, err := NewFRPToken(badSigner{}, vecServer1, vecRunID, 1); err == nil {
		t.Fatal("accepted a non-Ed25519 signer")
	}
}

type badSigner struct{}

func (badSigner) Public() crypto.PublicKey { return []byte("x") }
func (badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("no")
}

func TestRotationRoundTrip(t *testing.T) {
	old, nw := genKey(t), genKey(t)
	r, err := NewRotation(old, nw, vecServer1, 100)
	if err != nil {
		t.Fatal(err)
	}
	oldPub := old.Public().(ed25519.PublicKey)
	lookup := func(kid string) (RegistryEntry, bool) {
		if kid != KeyID(oldPub) {
			return RegistryEntry{}, false
		}
		return RegistryEntry{ServerID: vecServer1, PublicKey: oldPub, Status: StatusActive}, true
	}
	b := mustJSON(r)
	parsed, err := ParseRotation(b)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyRotation(parsed, vecServer1, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NewPublic.Equal(nw.Public()) || res.IAT != 100 {
		t.Fatal("wrong result")
	}
	again, _ := NewRotation(old, nw, vecServer1, 100)
	if again != r {
		t.Fatal("rotation is not deterministic for the same keys and iat")
	}
	if _, err := NewRotation(old, old, vecServer1, 100); CodeOf(err) != CodeBadKey {
		t.Fatalf("same key: %v", err)
	}
}

func TestErrorIs(t *testing.T) {
	err := fail(CodeExpired, "x")
	if !errors.Is(err, &Error{Code: CodeExpired}) || errors.Is(err, &Error{Code: CodeMalformed}) {
		t.Fatal("errors.Is by code")
	}
	if CodeOf(errors.New("plain")) != "" {
		t.Fatal("plain error has a code")
	}
}

var fprRe = regexp.MustCompile(`^SW-[0-9A-F]{4}-[0-9A-F]{4}$`)

// Property: every generated key passes the public key checks, has a
// 43-character key ID and a fingerprint in the display format that is the
// prefix of the key ID's digest.
func TestKeyProperties(t *testing.T) {
	for range 500 {
		pub := genKey(t).Public().(ed25519.PublicKey)
		if err := CheckPublicKey(pub); err != nil {
			t.Fatalf("generated key refused: %v", err)
		}
		kid := KeyID(pub)
		if len(kid) != 43 || !ValidID(kid) {
			t.Fatalf("key id %q", kid)
		}
		fp := Fingerprint(pub)
		if !fprRe.MatchString(fp) {
			t.Fatalf("fingerprint %q", fp)
		}
		d, _ := b64Decode(kid)
		if want := strings.ToUpper(hex.EncodeToString(d[:4])); fp != "SW-"+want[:4]+"-"+want[4:] {
			t.Fatalf("fingerprint %s is not the digest prefix of %s", fp, kid)
		}
	}
}

// Property: fingerprints of distinct deterministic keys are spread evenly
// over the hex digits and collide only at the birthday rate of 32 bits.
func TestFingerprintDistribution(t *testing.T) {
	const n = 20000
	seen := make(map[string]bool, n)
	var digits [16]int
	collisions := 0
	for i := range n {
		var seed [32]byte
		seed[0], seed[1], seed[2] = byte(i), byte(i>>8), byte(i>>16)
		fp := Fingerprint(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
		if seen[fp] {
			collisions++
		}
		seen[fp] = true
		for _, c := range strings.ReplaceAll(fp[3:], "-", "") {
			digits[strings.IndexRune("0123456789ABCDEF", c)]++
		}
	}
	// Expected collisions: n^2 / 2^33, about 0.05.
	if collisions > 2 {
		t.Fatalf("%d fingerprint collisions among %d keys", collisions, n)
	}
	expected := float64(n*8) / 16
	for d, c := range digits {
		if diff := float64(c) - expected; diff > expected*0.05 || diff < -expected*0.05 {
			t.Errorf("hex digit %x appears %d times, expected about %.0f", d, c, expected)
		}
	}
}

func TestDecodeObjectRules(t *testing.T) {
	type obj struct {
		A string `json:"a"`
		B int64  `json:"b"`
	}
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{`{"a":"x","b":1}`, true},
		{`{"a":"x"}`, false},
		{`{"a":"x","b":1,"c":2}`, false},
		{`{"a":"x","A":"y","b":1}`, false},
		{`{"a":"x","a":"y","b":1}`, false},
		{`{"a":"x","b":1} `, true},
		{`{"a":"x","b":1}x`, false},
		{`{"a":null,"b":1}`, false},
		{`{"a":"x","b":1e3}`, false},
		{`{"a":"x","b":"1"}`, false},
		{`[1]`, false},
		{`{"a":"x","b":1,"n":[[[[[[[[[]]]]]]]]]}`, false},
	} {
		var o obj
		err := decodeObject([]byte(tc.in), &o, []string{"a", "b"})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok=%v", tc.in, err, tc.ok)
		}
	}
}

func TestB64Strict(t *testing.T) {
	for _, s := range []string{"AA==", "AB", "A+", "A/", "AA\n", "A\rA"} {
		if _, err := b64Decode(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if b, err := b64Decode("AA"); err != nil || len(b) != 1 {
		t.Fatal("refused canonical input")
	}
}

func TestKeySetLookup(t *testing.T) {
	ks, err := VerifyKeySet(vecKeySet(5), parseRoots(t, vecRoots()), 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key, role string
		code      Code
	}{
		{"control-1", RoleControl, ""},
		{"control-2", RoleControl, ""},
		{"control-old", RoleControl, CodeKeyRevoked},
		{"visitor-1", RoleControl, CodeWrongKeyRole},
		{"edge-1", RoleEdge, ""},
		{"root-primary", RoleControl, CodeUnknownKey},
	} {
		_, err := ks.Lookup(vecKID(tc.key), tc.role)
		if CodeOf(err) != tc.code {
			t.Errorf("%s/%s: %v, want %q", tc.key, tc.role, err, tc.code)
		}
	}
}
