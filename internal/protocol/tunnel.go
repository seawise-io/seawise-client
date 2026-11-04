package protocol

import "crypto"

// Tunnel statement types: protocol flags and device state are signed by a
// control key, RouteSets by an edge key.
const (
	TypFlags    = "sw-tunnel-flags+jws"
	TypState    = "sw-state+jwt"
	TypRouteSet = "sw-routeset+jws"

	MaxFlagsSize    = 16384
	MaxStateSize    = maxTokenSize
	MaxRouteSetSize = 61440
)

// VerifyKeyed checks a compact JWS of typ whose kid names a key of role in
// the key set, and returns the payload and the key's name in the set. The
// payload is not parsed.
func VerifyKeyed(token, typ, role string, maxSize int, ks *KeySet) ([]byte, string, error) {
	if ks == nil {
		return nil, "", fail(CodeUnknownKey, "no key set")
	}
	t, err := parseJWS(token, typ, "kid", maxSize)
	if err != nil {
		return nil, "", err
	}
	pub, err := ks.Lookup(t.kid, role)
	if err != nil {
		return nil, "", err
	}
	if err := t.verify(pub); err != nil {
		return nil, "", err
	}
	name := ""
	for _, e := range ks.Keys {
		if e.KID == t.kid {
			name = e.Name
			break
		}
	}
	return t.payload, name, nil
}

// NewKeyed signs claims as a compact JWS of typ with the signer's kid; the
// claims are serialised in their own field order.
func NewKeyed(s crypto.Signer, typ string, claims any) (string, error) {
	return signJWS(s, typ, false, claims)
}
