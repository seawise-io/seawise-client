//go:build dev

package transport

import (
	"testing"

	"github.com/seawise/client/internal/protocol"
)

func TestDevBuildAlsoDialsLocalhostPoolDomains(t *testing.T) {
	l := edgeList(t, edgeEntry{"edge-us-east-1", protocol.StatusActive, seedKey("a")})
	for _, name := range []string{"tunnel-us-east.seawise.dev", "tunnel-us-east.svc.sw2.localhost"} {
		if r, ok := l.Region(name); !ok || r != "us-east" {
			t.Errorf("%q: %q %v", name, r, ok)
		}
	}
	for _, name := range []string{"tunnel-us-east.localhost.example", "tunnel-us-east..localhost", "tunnel-eu-west.svc.sw2.localhost", "tunnel-us-east.example.test"} {
		if _, ok := l.Region(name); ok {
			t.Errorf("%q allowed", name)
		}
	}
}
