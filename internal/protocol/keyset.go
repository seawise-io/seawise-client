package protocol

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
)

// Key set roles.
const (
	RoleControl  = "control"
	RoleSnapshot = "snapshot"
	RoleVisitor  = "visitor"
	RoleEdge     = "edge"
	RoleRelease  = "release"
)

const maxKeySetKeys = 256

var knownRoles = map[string]bool{RoleControl: true, RoleSnapshot: true, RoleVisitor: true, RoleEdge: true, RoleRelease: true}

// KeySetEntry is one key in a key set.
type KeySetEntry struct {
	KID    string `json:"kid"`
	Role   string `json:"role"`
	X      string `json:"x"`
	Status string `json:"status"`
	Name   string `json:"name,omitempty"`
}

type keySetWire struct {
	Version int64             `json:"version"`
	IAT     int64             `json:"iat"`
	Keys    []json.RawMessage `json:"keys"`
}

type keySetSign struct {
	Version int64         `json:"version"`
	IAT     int64         `json:"iat"`
	Keys    []KeySetEntry `json:"keys"`
}

// KeySet is a verified key set.
type KeySet struct {
	Version int64
	IAT     int64
	// Digest is the SHA-256 of the payload, kept to detect a different set
	// published under the same version.
	Digest [32]byte
	Keys   []KeySetEntry
	pubs   map[string]ed25519.PublicKey
}

// NewKeySet signs a key set with a root key.
func NewKeySet(root crypto.Signer, version, iat int64, keys []KeySetEntry) (string, error) {
	return signJWS(root, TypKeySet, false, keySetSign{Version: version, IAT: iat, Keys: keys})
}

// VerifyKeySet checks a key set against the pinned roots. lastVersion and
// lastDigest describe the last accepted set (version 0 when none).
func VerifyKeySet(token string, roots []ed25519.PublicKey, lastVersion int64, lastDigest [32]byte) (*KeySet, error) {
	t, err := parseJWS(token, TypKeySet, "kid", maxKeySetSize)
	if err != nil {
		return nil, err
	}
	var root ed25519.PublicKey
	for _, r := range roots {
		if KeyID(r) == t.kid {
			root = r
			break
		}
	}
	if root == nil {
		return nil, fail(CodeUnknownKey, "key set is not signed by a pinned root")
	}
	if err := t.verify(root); err != nil {
		return nil, err
	}
	var w keySetWire
	if err := decodeObject(t.payload, &w, []string{"version", "iat", "keys"}); err != nil {
		return nil, err
	}
	if w.Version < 1 || w.Version > maxTime {
		return nil, fail(CodeMalformed, "version out of range")
	}
	if err := checkTime("iat", w.IAT); err != nil {
		return nil, err
	}
	if len(w.Keys) == 0 || len(w.Keys) > maxKeySetKeys {
		return nil, fail(CodeMalformed, "key set must hold 1 to %d keys", maxKeySetKeys)
	}
	ks := &KeySet{Version: w.Version, IAT: w.IAT, Digest: sha256.Sum256(t.payload), pubs: map[string]ed25519.PublicKey{}}
	for _, raw := range w.Keys {
		e, pub, err := parseKeySetEntry(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := ks.pubs[e.KID]; dup {
			return nil, fail(CodeMalformed, "duplicate kid in key set")
		}
		ks.pubs[e.KID] = pub
		ks.Keys = append(ks.Keys, e)
	}
	if w.Version < lastVersion || (w.Version == lastVersion && ks.Digest != lastDigest) {
		return nil, fail(CodeRollback, "key set version %d is older than %d", w.Version, lastVersion)
	}
	return ks, nil
}

func parseKeySetEntry(raw []byte) (KeySetEntry, ed25519.PublicKey, error) {
	var e KeySetEntry
	if err := decodeObject(raw, &e, []string{"kid", "role", "x", "status"}, "name"); err != nil {
		return e, nil, err
	}
	pub, err := ParsePublicKey(e.X)
	if err != nil {
		return e, nil, err
	}
	if e.KID != KeyID(pub) {
		return e, nil, fail(CodeMalformed, "kid is not the thumbprint of x")
	}
	if !knownRoles[e.Role] {
		return e, nil, fail(CodeMalformed, "unknown role")
	}
	switch e.Status {
	case StatusActive, StatusNext, StatusRevoked:
	default:
		return e, nil, fail(CodeMalformed, "unknown status")
	}
	if (e.Role == RoleEdge) != (e.Name != "") {
		return e, nil, fail(CodeMalformed, "name is required for edge keys only")
	}
	if e.Name != "" && !edgeNameRe.MatchString(e.Name) {
		return e, nil, fail(CodeMalformed, "edge name syntax")
	}
	return e, pub, nil
}

// Lookup returns the key for kid if it has role and is active or announced.
func (ks *KeySet) Lookup(kid, role string) (ed25519.PublicKey, error) {
	for _, e := range ks.Keys {
		if e.KID != kid {
			continue
		}
		if e.Role != role {
			return nil, fail(CodeWrongKeyRole, "key has role %s, want %s", e.Role, role)
		}
		if e.Status == StatusRevoked {
			return nil, fail(CodeKeyRevoked, "key is revoked")
		}
		return ks.pubs[kid], nil
	}
	return nil, fail(CodeUnknownKey, "key is not in the key set")
}
