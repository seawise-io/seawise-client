package transport

import (
	"crypto/ed25519"
	"regexp"
	"strings"

	"github.com/seawise/client/internal/protocol"
)

// Pool names are tunnel-<region>.seawise.dev.
const (
	poolPrefix = "tunnel-"
	poolSuffix = ".seawise.dev"
)

var edgeIDRe = regexp.MustCompile(`^edge-([a-z]+-[a-z]+)-[0-9]{1,4}$`)

// EdgeList is the signed edge list: the edge entries of a verified key set
// that are active or announced. Their names are the only edge ids accepted
// in HelloAck, and their regions the only pool names dialled.
type EdgeList struct {
	keys    map[string][]ed25519.PublicKey
	regions map[string]bool
}

// NewEdgeList takes the edge list from a key set returned by
// protocol.VerifyKeySet. Entries whose name is not an edge id are ignored.
func NewEdgeList(ks *protocol.KeySet) (*EdgeList, error) {
	if ks == nil {
		return nil, ErrNoEdgeList
	}
	l := &EdgeList{keys: map[string][]ed25519.PublicKey{}, regions: map[string]bool{}}
	for _, e := range ks.Keys {
		if e.Role != protocol.RoleEdge || (e.Status != protocol.StatusActive && e.Status != protocol.StatusNext) {
			continue
		}
		region, ok := regionOf(e.Name)
		if !ok {
			continue
		}
		pub, err := ks.Lookup(e.KID, protocol.RoleEdge)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		l.keys[e.Name] = append(l.keys[e.Name], pub)
		l.regions[region] = true
	}
	if len(l.keys) == 0 {
		return nil, ErrNoEdgeList
	}
	return l, nil
}

func regionOf(edgeID string) (string, bool) {
	m := edgeIDRe.FindStringSubmatch(edgeID)
	if m == nil || len(edgeID) > 63 {
		return "", false
	}
	return m[1], true
}

// PoolName is the tunnel name of a region.
func PoolName(region string) string { return poolPrefix + region + poolSuffix }

// Region returns the region of a pool name the list allows.
func (l *EdgeList) Region(name string) (string, bool) {
	if l == nil || !strings.HasPrefix(name, poolPrefix) || !strings.HasSuffix(name, poolSuffix) {
		return "", false
	}
	region := name[len(poolPrefix) : len(name)-len(poolSuffix)]
	return region, l.regions[region]
}

// Keys returns the keys of an edge id in the list.
func (l *EdgeList) Keys(edgeID string) []ed25519.PublicKey {
	if l == nil {
		return nil
	}
	return l.keys[edgeID]
}
