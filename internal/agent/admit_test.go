package agent

import (
	"net/netip"
	"testing"

	"github.com/seawise/client/internal/store"
)

func TestAdmit(t *testing.T) {
	targets := []store.Target{
		{LocalID: "ok", Host: "192.168.1.20", Port: 80, Subdomain: "a", Source: store.SourceLocal},
		{LocalID: "name", Host: "jellyfin.lan", Port: 8096, Subdomain: "b", Source: store.SourceLocal},
		{LocalID: "off", Host: "192.168.1.21", Port: 80, Subdomain: "c", Disabled: true},
		{LocalID: "unregistered", Host: "192.168.1.22", Port: 80},
		{LocalID: "meta", Host: "169.254.169.254", Port: 80, Subdomain: "d"},
		{LocalID: "port0", Host: "192.168.1.23", Port: 0, Subdomain: "e"},
		{LocalID: "port", Host: "192.168.1.23", Port: 65536, Subdomain: "f"},
		{LocalID: "public", Host: "93.184.216.34", Port: 443, Subdomain: "g", Source: store.SourceLocal},
		{LocalID: "bracket", Host: "[::1]", Port: 80, Subdomain: "h", Allowed: []string{"loopback"}},
		{LocalID: "localhost", Host: "LocalHost.", Port: 80, Subdomain: "i", Allowed: []string{"loopback"}},
		{LocalID: "low", Host: "192.168.1.24", Port: 1, Subdomain: "j"},
		{LocalID: "high", Host: "192.168.1.24", Port: 65535, Subdomain: "k"},
	}
	ok, refused := admit(targets, []netip.Addr{netip.MustParseAddr("192.168.1.1")})
	got := map[string]bool{}
	for _, t := range ok {
		got[t.LocalID] = true
	}
	for _, id := range []string{"ok", "name", "public", "bracket", "localhost", "low", "high"} {
		if !got[id] {
			t.Errorf("%s not admitted", id)
		}
	}
	reasons := map[string]string{}
	for _, r := range refused {
		reasons[r.LocalID] = r.Reason
	}
	if len(ok) != 7 || len(reasons) != 3 || reasons["meta"] == "" || reasons["port0"] != "invalid port" || reasons["port"] != "invalid port" {
		t.Fatalf("admitted %v refused %v", got, reasons)
	}
}

func TestLiteral(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1": "127.0.0.1", "[::1]": "::1", "localhost": "127.0.0.1", "LOCALHOST.": "127.0.0.1"} {
		if a, ok := literal(in); !ok || a.String() != want {
			t.Errorf("%s: %v %v", in, a, ok)
		}
	}
	if _, ok := literal("app.lan"); ok {
		t.Fatal("name parsed as an address")
	}
}
