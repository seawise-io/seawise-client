package transport

import (
	"errors"
	"testing"

	"github.com/seawise/client/internal/protocol"
)

func TestEdgeListFromVerifiedKeySet(t *testing.T) {
	a, b, c, d := seedKey("a"), seedKey("b"), seedKey("c"), seedKey("d")
	l := edgeList(t,
		edgeEntry{"edge-us-east-1", protocol.StatusActive, a},
		edgeEntry{"edge-us-east-1", protocol.StatusNext, b},
		edgeEntry{"edge-eu-west-2", protocol.StatusRevoked, c},
		edgeEntry{"edge-fsn1-1", protocol.StatusActive, d},
	)
	if r, ok := l.Region("tunnel-us-east.seawise.dev"); !ok || r != "us-east" {
		t.Fatal(r, ok)
	}
	for _, name := range []string{
		"tunnel-eu-west.seawise.dev", // revoked only
		"tunnel-fsn1.seawise.dev",    // not an edge id
		"tunnel-us-east.seawise.dev.",
		"TUNNEL-US-EAST.SEAWISE.DEV",
		"tunnel-us-east.seawise.dev.evil.example",
		"tunnel-us-east.seawise.io",
		"us-east.seawise.dev",
		"tunnel-.seawise.dev",
		"",
	} {
		if _, ok := l.Region(name); ok {
			t.Errorf("%q allowed", name)
		}
	}
	if k := l.Keys("edge-us-east-1"); len(k) != 2 || !k[0].Equal(pubOf(a)) || !k[1].Equal(pubOf(b)) {
		t.Fatal("active and next keys")
	}
	if l.Keys("edge-eu-west-2") != nil || l.Keys("edge-fsn1-1") != nil || l.Keys("edge-us-east-9") != nil {
		t.Fatal("unlisted keys returned")
	}
	if PoolName("us-east") != "tunnel-us-east.seawise.dev" {
		t.Fatal(PoolName("us-east"))
	}
	var nilList *EdgeList
	if _, ok := nilList.Region("tunnel-us-east.seawise.dev"); ok || nilList.Keys("edge-us-east-1") != nil {
		t.Fatal("nil list allows")
	}
}

func TestEdgeListRefusesUnverified(t *testing.T) {
	if _, err := NewEdgeList(nil); !errors.Is(err, ErrNoEdgeList) {
		t.Fatal(err)
	}
	// A hand-built key set has no verified keys behind its entries.
	ks := &protocol.KeySet{Keys: []protocol.KeySetEntry{{KID: protocol.KeyID(pubOf(seedKey("x"))), Role: protocol.RoleEdge,
		Status: protocol.StatusActive, Name: "edge-us-east-1"}}}
	if _, err := NewEdgeList(ks); !errors.Is(err, ErrNoEdgeList) {
		t.Fatal(err)
	}
	if _, err := NewEdgeList(keySet(t, edgeEntry{"edge-us-east-1", protocol.StatusRevoked, seedKey("r")})); !errors.Is(err, ErrNoEdgeList) {
		t.Fatal(err)
	}
}

func TestRegionOf(t *testing.T) {
	for id, want := range map[string]string{"edge-us-east-0": "us-east", "edge-eu-central-1234": "eu-central"} {
		if r, ok := regionOf(id); !ok || r != want {
			t.Error(id, r, ok)
		}
	}
	for _, id := range []string{"edge-us-east-12345", "edge-us-1", "edge-us-east-a", "Edge-us-east-1", "xedge-us-east-1", "edge-us-east-1 "} {
		if _, ok := regionOf(id); ok {
			t.Error(id)
		}
	}
}
