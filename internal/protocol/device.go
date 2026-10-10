package protocol

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"slices"
)

// Registry key status values.
const (
	StatusActive  = "active"
	StatusNext    = "next"
	StatusRevoked = "revoked"
)

// FRPTokenLifetime is how long an frp login token is accepted after iat.
// The agent mints tokens itself and re-mints at half life, so the lifetime
// only bounds the use of a stolen token; 72 hours still tolerates a weekend
// without signed time on a device with a drifting clock.
const FRPTokenLifetime = 72 * 3600

// RegistryEntry is what a verifier knows about a device key.
type RegistryEntry struct {
	ServerID  string
	PublicKey ed25519.PublicKey
	// Status is "active" for a usable key; anything else is refused.
	Status string
	// ValidFrom is when the key was registered (unix seconds).
	ValidFrom int64
}

// FRPClaims are the claims of an frp login token.
type FRPClaims struct {
	ServerID string `json:"server_id"`
	KeyID    string `json:"key_id"`
	IAT      int64  `json:"iat"`
	RunID    string `json:"run_id"`
}

var frpMembers = []string{"server_id", "key_id", "iat", "run_id"}

func (c *FRPClaims) check() error {
	if err := checkServerID(c.ServerID); err != nil {
		return err
	}
	if err := checkTime("iat", c.IAT); err != nil {
		return err
	}
	return checkID("run_id", c.RunID)
}

// NewFRPToken mints an frp login token with the device key.
func NewFRPToken(s crypto.Signer, serverID, runID string, iat int64) (string, error) {
	pub, err := signerPublic(s)
	if err != nil {
		return "", err
	}
	c := FRPClaims{ServerID: serverID, KeyID: KeyID(pub), IAT: iat, RunID: runID}
	if err := c.check(); err != nil {
		return "", err
	}
	return signJWS(s, TypFRP, false, c)
}

// VerifyFRPToken checks a login token presented by loginServerID. lookup
// returns the registry entry for a key ID. runConflict reports whether the
// server has a live session under a different run_id; it may be nil only
// where sessions are not tracked (tests).
func VerifyFRPToken(token, loginServerID string, lookup func(kid string) (RegistryEntry, bool), now int64, runConflict func(serverID, runID string) bool) (*FRPClaims, error) {
	t, err := parseJWS(token, TypFRP, "kid", maxTokenSize)
	if err != nil {
		return nil, err
	}
	e, err := registryKey(t, lookup)
	if err != nil {
		return nil, err
	}
	if e.Status != StatusActive {
		return nil, fail(CodeKeyRevoked, "key is not active")
	}
	var c FRPClaims
	if err := decodeObject(t.payload, &c, frpMembers); err != nil {
		return nil, err
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	if c.KeyID != t.kid {
		return nil, fail(CodeMalformed, "key_id differs from kid")
	}
	if c.ServerID != e.ServerID || c.ServerID != loginServerID {
		return nil, fail(CodeWrongServer, "token is for another server")
	}
	switch {
	case c.IAT > now+leewaySec:
		return nil, fail(CodeNotYetValid, "iat is in the future")
	case now-c.IAT > FRPTokenLifetime:
		return nil, fail(CodeExpired, "token older than its lifetime")
	case c.IAT < e.ValidFrom-leewaySec:
		return nil, fail(CodeBeforeKeyValid, "token issued before the key was registered")
	}
	if runConflict != nil && runConflict(c.ServerID, c.RunID) {
		return nil, fail(CodeRunConflict, "server has a live session from another run")
	}
	return &c, nil
}

// registryKey finds the signing key of t and verifies the signature. Status
// is left to the caller, so only the key holder learns that a key was
// revoked.
func registryKey(t *jws, lookup func(string) (RegistryEntry, bool)) (RegistryEntry, error) {
	e, ok := lookup(t.kid)
	if !ok || KeyID(e.PublicKey) != t.kid {
		return RegistryEntry{}, fail(CodeUnknownKey, "key is not registered")
	}
	if err := CheckPublicKey(e.PublicKey); err != nil {
		return RegistryEntry{}, fail(CodeUnknownKey, "registry key is invalid")
	}
	if err := t.verify(e.PublicKey); err != nil {
		return RegistryEntry{}, err
	}
	return e, nil
}

// Rotation replaces a device key: two tokens over the same payload, signed
// by the old and the new key.
type Rotation struct {
	Statement string `json:"statement"`
	PoP       string `json:"pop"`
}

// RotationClaims are the shared payload of a rotation.
type RotationClaims struct {
	ServerID string          `json:"server_id"`
	OldKID   string          `json:"old_kid"`
	NewJWK   json.RawMessage `json:"new_jwk"`
	IAT      int64           `json:"iat"`
}

var rotationMembers = []string{"server_id", "old_kid", "new_jwk", "iat"}

// RotationResult is a verified rotation.
type RotationResult struct {
	ServerID  string
	OldKeyID  string
	NewKeyID  string
	NewPublic ed25519.PublicKey
	IAT       int64
	// AlreadyApplied is set when r is byte-identical to the rotation the
	// server already accepted from this key: a retry, answered as success.
	AlreadyApplied bool
}

// RotationCheck is what the verifier knows about the requesting server.
type RotationCheck struct {
	ServerID string
	Lookup   func(kid string) (RegistryEntry, bool)
	// PreviousKeyIDs are every key ID ever registered for the server; a
	// rotation back to one of them is refused.
	PreviousKeyIDs []string
	// Applied returns the rotation already accepted from oldKID, if any.
	Applied func(oldKID string) (Rotation, bool)
}

// NewRotation signs a rotation from oldKey to newKey.
func NewRotation(oldKey, newKey crypto.Signer, serverID string, iat int64) (Rotation, error) {
	oldPub, err := signerPublic(oldKey)
	if err != nil {
		return Rotation{}, err
	}
	newPub, err := signerPublic(newKey)
	if err != nil {
		return Rotation{}, err
	}
	if oldPub.Equal(newPub) {
		return Rotation{}, fail(CodeBadKey, "new key equals old key")
	}
	if err := checkServerID(serverID); err != nil {
		return Rotation{}, err
	}
	if err := checkTime("iat", iat); err != nil {
		return Rotation{}, err
	}
	c := RotationClaims{ServerID: serverID, OldKID: KeyID(oldPub), NewJWK: mustJSON(PublicJWK(newPub)), IAT: iat}
	st, err := signJWS(oldKey, TypRotate, false, c)
	if err != nil {
		return Rotation{}, err
	}
	pop, err := signJWS(newKey, TypRotatePoP, false, c)
	if err != nil {
		return Rotation{}, err
	}
	return Rotation{Statement: st, PoP: pop}, nil
}

// ParseRotation decodes the JSON form of a rotation.
func ParseRotation(b []byte) (Rotation, error) {
	if len(b) > 2*maxTokenSize+64 {
		return Rotation{}, fail(CodeTooLarge, "rotation too large")
	}
	var r Rotation
	if err := decodeObject(b, &r, []string{"statement", "pop"}); err != nil {
		return Rotation{}, err
	}
	return r, nil
}

// VerifyRotation checks a rotation sent by the server in c.
func VerifyRotation(r Rotation, c RotationCheck) (*RotationResult, error) {
	st, err := parseJWS(r.Statement, TypRotate, "kid", maxTokenSize)
	if err != nil {
		return nil, err
	}
	pop, err := parseJWS(r.PoP, TypRotatePoP, "kid", maxTokenSize)
	if err != nil {
		return nil, err
	}
	if st.payloadB64 != pop.payloadB64 {
		return nil, fail(CodeMalformed, "statement and pop payloads differ")
	}
	old, err := registryKey(st, c.Lookup)
	if err != nil {
		return nil, err
	}
	applied := false
	if c.Applied != nil {
		prev, ok := c.Applied(st.kid)
		applied = ok && prev == r
	}
	if !applied && old.Status != StatusActive {
		return nil, fail(CodeKeyRevoked, "key is not active")
	}
	var cl RotationClaims
	if err := decodeObject(st.payload, &cl, rotationMembers); err != nil {
		return nil, err
	}
	if err := checkServerID(cl.ServerID); err != nil {
		return nil, err
	}
	if err := checkTime("iat", cl.IAT); err != nil {
		return nil, err
	}
	if cl.OldKID != st.kid {
		return nil, fail(CodeMalformed, "old_kid differs from kid")
	}
	if cl.ServerID != c.ServerID || old.ServerID != c.ServerID {
		return nil, fail(CodeWrongServer, "rotation is for another server")
	}
	newPub, err := parseJWK(cl.NewJWK)
	if err != nil {
		return nil, err
	}
	if newPub.Equal(old.PublicKey) {
		return nil, fail(CodeBadKey, "new key equals old key")
	}
	newKID := KeyID(newPub)
	if !applied && slices.Contains(c.PreviousKeyIDs, newKID) {
		return nil, fail(CodeBadKey, "new key was registered before")
	}
	if pop.kid != newKID {
		return nil, fail(CodeMalformed, "pop kid is not the new key")
	}
	if err := pop.verify(newPub); err != nil {
		return nil, err
	}
	return &RotationResult{ServerID: cl.ServerID, OldKeyID: st.kid, NewKeyID: newKID, NewPublic: newPub, IAT: cl.IAT, AlreadyApplied: applied}, nil
}
