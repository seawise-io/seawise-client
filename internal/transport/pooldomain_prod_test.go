//go:build !dev

package transport

import (
	"testing"

	"github.com/seawise/client/internal/protocol"
)

func TestReleaseBuildDialsOnlyTheProductionPoolDomain(t *testing.T) {
	l := edgeList(t, edgeEntry{"edge-us-east-1", protocol.StatusActive, seedKey("a")})
	if r, ok := l.Region("tunnel-us-east.seawise.dev"); !ok || r != "us-east" {
		t.Fatal(r, ok)
	}
	for _, name := range []string{"tunnel-us-east.svc.sw2.localhost", "tunnel-us-east.localhost", "tunnel-us-east.example.test"} {
		if _, ok := l.Region(name); ok {
			t.Errorf("%q allowed in a release build", name)
		}
	}
}
