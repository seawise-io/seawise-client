package targetpolicy

import (
	"net/netip"
	"testing"
)

func FuzzClassify(f *testing.F) {
	for _, s := range []string{"169.254.169.254", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "::1", "10.0.0.1", "fe80::1%eth0",
		"::ffff:0:a9fe:a9fe", "2001:0:4136:e378:8000:63bf:5601:5601", "fd00::5efe:a9fe:a9fe"} {
		a := netip.MustParseAddr(s)
		b := a.As16()
		f.Add(b[:])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) != 16 && len(raw) != 4 {
			return
		}
		a, _ := netip.AddrFromSlice(raw)
		c, reason := Classify(a)
		u := a.Unmap()
		// Metadata and link-local never escape the forbidden class, in any
		// encoding.
		if u.Is4() {
			b := u.As4()
			if b[0] == 169 && b[1] == 254 && c != Forbidden {
				t.Fatalf("%s classified %s", a, c)
			}
		}
		if v4, ok := embeddedIPv4(u); ok {
			if inner, _ := Classify(v4); inner != Public && c != Forbidden {
				t.Fatalf("%s embeds %s %s but classified %s", a, v4, inner, c)
			}
		}
		if c == Forbidden && reason == "" {
			t.Fatal("forbidden without reason")
		}
		if c == Loopback && !u.IsLoopback() {
			t.Fatalf("%s loopback", a)
		}
		if (u.IsLinkLocalUnicast() || u.IsMulticast() || u.IsUnspecified()) && c != Forbidden {
			t.Fatalf("%s classified %s", a, c)
		}
	})
}

func FuzzParseRoutes(f *testing.F) {
	f.Add([]byte("Iface\tDestination\tGateway\nx\t00000000\t0101A8C0\n"))
	f.Add([]byte("00000000000000000000000000000000 00 0 00 fe800000000000000000000000000001\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, a := range append(parseIPv4Routes(b), parseIPv6Routes(b)...) {
			if !a.IsValid() || a.IsUnspecified() || a.Zone() != "" {
				t.Fatalf("bad gateway %v", a)
			}
		}
	})
}
