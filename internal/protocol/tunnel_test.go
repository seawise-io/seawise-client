package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func tunnelKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("tunnel statement test key: " + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func tunnelKeySet(t *testing.T) *KeySet {
	t.Helper()
	root := tunnelKey("root")
	entry := func(name, role, status string) KeySetEntry {
		pub := tunnelKey(name).Public().(ed25519.PublicKey)
		e := KeySetEntry{KID: KeyID(pub), Role: role, X: b64Encode(pub), Status: status}
		if role == RoleEdge {
			e.Name = name
		}
		return e
	}
	tok, err := NewKeySet(root, 3, 1700000000, []KeySetEntry{
		entry("control", RoleControl, StatusActive),
		entry("edge-us-east-0", RoleEdge, StatusActive),
		entry("control-old", RoleControl, StatusRevoked),
	})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := VerifyKeySet(tok, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestVerifyKeyed(t *testing.T) {
	ks := tunnelKeySet(t)
	claims := map[string]any{"a": 1}
	ok, _ := NewKeyed(tunnelKey("control"), TypFlags, claims)
	p, name, err := VerifyKeyed(ok, TypFlags, RoleControl, MaxFlagsSize, ks)
	if err != nil || string(p) != `{"a":1}` || name != "" {
		t.Fatal(string(p), name, err)
	}
	edge, _ := NewKeyed(tunnelKey("edge-us-east-0"), TypRouteSet, claims)
	if _, name, err := VerifyKeyed(edge, TypRouteSet, RoleEdge, MaxRouteSetSize, ks); err != nil || name != "edge-us-east-0" {
		t.Fatal(name, err)
	}
	other, _ := NewKeyed(tunnelKey("stranger"), TypFlags, claims)
	revoked, _ := NewKeyed(tunnelKey("control-old"), TypFlags, claims)
	wrongTyp, _ := NewKeyed(tunnelKey("control"), TypState, claims)
	tampered := ok[:len(ok)-2] + "AA"
	cases := map[string]struct {
		tok, typ, role string
		max            int
		ks             *KeySet
		code           Code
	}{
		"unknown key":   {other, TypFlags, RoleControl, MaxFlagsSize, ks, CodeUnknownKey},
		"revoked key":   {revoked, TypFlags, RoleControl, MaxFlagsSize, ks, CodeKeyRevoked},
		"wrong role":    {edge, TypRouteSet, RoleControl, MaxRouteSetSize, ks, CodeWrongKeyRole},
		"wrong typ":     {wrongTyp, TypFlags, RoleControl, MaxFlagsSize, ks, CodeBadTyp},
		"bad signature": {tampered, TypFlags, RoleControl, MaxFlagsSize, ks, CodeBadSignature},
		"too large":     {ok, TypFlags, RoleControl, len(ok) - 1, ks, CodeTooLarge},
		"no key set":    {ok, TypFlags, RoleControl, MaxFlagsSize, nil, CodeUnknownKey},
		"malformed":     {strings.Repeat("a", 10), TypFlags, RoleControl, MaxFlagsSize, ks, CodeMalformed},
	}
	for name, c := range cases {
		_, _, err := VerifyKeyed(c.tok, c.typ, c.role, c.max, c.ks)
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	if _, _, err := VerifyKeyed(ok, TypFlags, RoleControl, len(ok), ks); err != nil {
		t.Fatal("exact size refused", err)
	}
}
