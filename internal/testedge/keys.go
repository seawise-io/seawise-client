package testedge

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/seawise/client/internal/protocol"
)

// Keys are the key-set root, the control key and the edge key, derived
// from a seed so separate processes agree on them.
type Keys struct {
	Root, Control, Edge ed25519.PrivateKey
	// EdgeID names the edge key in the key set; its region decides which
	// tunnel names the agent accepts.
	EdgeID string
}

// NewKeys derives the keys from seed.
func NewKeys(seed, edgeID string) Keys {
	k := func(name string) ed25519.PrivateKey {
		s := sha256.Sum256([]byte("testedge/" + seed + "/" + name))
		return ed25519.NewKeyFromSeed(s[:])
	}
	return Keys{Root: k("root"), Control: k("control"), Edge: k("edge"), EdgeID: edgeID}
}

// RootPublic is the key-set root the agent pins.
func (k Keys) RootPublic() ed25519.PublicKey { return k.Root.Public().(ed25519.PublicKey) }

// KeySet is the root-signed key set naming the control and edge keys.
func (k Keys) KeySet(version, iat int64) (string, error) {
	entry := func(priv ed25519.PrivateKey, role, name string) protocol.KeySetEntry {
		pub := priv.Public().(ed25519.PublicKey)
		return protocol.KeySetEntry{KID: protocol.KeyID(pub), Role: role, X: protocol.PublicJWK(pub).X, Status: protocol.StatusActive, Name: name}
	}
	return protocol.NewKeySet(k.Root, version, iat, []protocol.KeySetEntry{
		entry(k.Control, protocol.RoleControl, ""), entry(k.Edge, protocol.RoleEdge, k.EdgeID),
	})
}
