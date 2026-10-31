package visitor

import (
	"crypto/ed25519"

	"github.com/seawise/client/internal/protocol"
)

type key struct {
	pub  ed25519.PublicKey
	name string
}

// Keys indexes the visitor and edge keys of one verified key set by kid.
// Revoked keys and keys of other roles are left out.
type Keys struct {
	set      *protocol.KeySet
	visitors map[string]key
	edges    map[string]key
}

// NewKeys indexes ks; a nil set gives no keys.
func NewKeys(ks *protocol.KeySet) *Keys {
	k := &Keys{set: ks, visitors: map[string]key{}, edges: map[string]key{}}
	if ks == nil {
		return k
	}
	for _, e := range ks.Keys {
		into := k.visitors
		if e.Role == protocol.RoleEdge {
			into = k.edges
		} else if e.Role != protocol.RoleVisitor {
			continue
		}
		pub, err := ks.Lookup(e.KID, e.Role)
		if err != nil {
			continue
		}
		into[e.KID] = key{pub: pub, name: e.Name}
	}
	return k
}

func (k *Keys) visitor(kid string) (key, bool) {
	e, ok := k.visitors[kid]
	return e, ok
}

func (k *Keys) edge(kid string) (key, bool) {
	e, ok := k.edges[kid]
	return e, ok
}
