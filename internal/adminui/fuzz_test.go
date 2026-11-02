package adminui

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzIsTLSClientHello(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Add([]byte("GET / HTTP/1.1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		want := len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
		if isTLSClientHello(b) != want {
			t.Fatalf("%x", b)
		}
	})
}

func FuzzHostAllowed(f *testing.F) {
	for _, s := range []string{"localhost:8082", "192.168.1.1", "[::1]:8082", "nas.local", "evil.example", "nas", "a.local.evil", "[fe80::1%25eth0]", ".local", "localhost.:1"} {
		f.Add(s)
	}
	extra := map[string]bool{"nas": true}
	f.Fuzz(func(t *testing.T, raw string) {
		if !hostAllowed(raw, extra) {
			return
		}
		h := normalizeHost(raw)
		if _, err := netip.ParseAddr(h); err == nil {
			return
		}
		if h == "localhost" || h == "nas" || (strings.HasSuffix(h, ".local") && validDNSName(h)) {
			return
		}
		t.Fatalf("%q allowed as %q", raw, h)
	})
}

func FuzzCertNames(f *testing.F) {
	f.Add("nas,NAS.local,*.x,10.0.0.1,a..b")
	f.Fuzz(func(t *testing.T, in string) {
		out := sanitizeNames(strings.Split(in, ","))
		if len(out) > maxCertNames {
			t.Fatal("too many names")
		}
		for _, n := range out {
			if !validDNSName(n) || n != strings.ToLower(n) || strings.ContainsAny(n, "*: ") {
				t.Fatalf("bad name %q", n)
			}
			if _, err := netip.ParseAddr(n); err == nil {
				t.Fatalf("IP as DNS name %q", n)
			}
		}
	})
}
