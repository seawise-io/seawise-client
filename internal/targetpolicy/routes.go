package targetpolicy

import (
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
)

const maxRouteFile = 1 << 20

// Gateways returns the default-route gateways of this host. On systems
// without /proc it returns nothing, and gateways are not treated specially.
func Gateways() []netip.Addr {
	var out []netip.Addr
	if b, err := readSmall("/proc/net/route"); err == nil {
		out = append(out, parseIPv4Routes(b)...)
	}
	if b, err := readSmall("/proc/net/ipv6_route"); err == nil {
		out = append(out, parseIPv6Routes(b)...)
	}
	return out
}

func readSmall(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if len(b) > maxRouteFile {
		b = b[:maxRouteFile]
	}
	return b, err
}

// parseIPv4Routes reads /proc/net/route: little-endian hex destination and
// gateway columns; default routes have destination 0.
func parseIPv4Routes(b []byte) []netip.Addr {
	var out []netip.Addr
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 3 || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		a := netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		if !a.IsUnspecified() {
			out = appendUnique(out, a)
		}
	}
	return out
}

// parseIPv6Routes reads /proc/net/ipv6_route: destination, prefix length,
// source, source length, next hop, all hex.
func parseIPv6Routes(b []byte) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[1] != "00" || strings.Trim(f[0], "0") != "" {
			continue
		}
		raw, err := hex.DecodeString(f[4])
		if err != nil || len(raw) != 16 {
			continue
		}
		a := netip.AddrFrom16([16]byte(raw))
		if !a.IsUnspecified() {
			out = appendUnique(out, a.WithZone(""))
		}
	}
	return out
}

func appendUnique(s []netip.Addr, a netip.Addr) []netip.Addr {
	for _, x := range s {
		if x == a {
			return s
		}
	}
	return append(s, a)
}
