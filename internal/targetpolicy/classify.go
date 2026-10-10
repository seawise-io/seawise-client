// Package targetpolicy decides which addresses an app may reach. The agent
// applies it twice: when it renders frpc's config (literal addresses and
// unconfirmed apps) and in the forwarding proxy's dialer, on the address
// actually connected to, for every connection.
package targetpolicy

import (
	"fmt"
	"net/netip"
	"sync/atomic"
)

type Class string

const (
	Forbidden Class = "forbidden"
	Loopback  Class = "loopback"
	Private   Class = "private"
	Public    Class = "public"
)

var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("192.0.0.192"),
	netip.MustParseAddr("fd00:ec2::254"), // AWS IPv6
	netip.MustParseAddr("168.63.129.16"), // Azure WireServer
	netip.MustParseAddr("fd20:ce::254"),  // GCP IPv6
}

type prefixReason struct {
	p      netip.Prefix
	reason string
}

func pfx(s, reason string) prefixReason { return prefixReason{netip.MustParsePrefix(s), reason} }

var forbiddenPrefixes = []prefixReason{
	pfx("0.0.0.0/8", "this-network address"),
	pfx("169.254.0.0/16", "link-local address"),
	pfx("224.0.0.0/4", "multicast address"),
	pfx("240.0.0.0/4", "reserved or broadcast address"),
	pfx("192.0.0.0/24", "protocol-assignment address"),
	pfx("192.0.2.0/24", "documentation address"),
	pfx("198.51.100.0/24", "documentation address"),
	pfx("203.0.113.0/24", "documentation address"),
	pfx("198.18.0.0/15", "benchmarking address"),
	pfx("::/128", "unspecified address"),
	pfx("::/96", "deprecated IPv4-compatible address"),
	pfx("100::/64", "discard address"),
	pfx("fe80::/10", "link-local address"),
	pfx("fec0::/10", "site-local address"),
	pfx("ff00::/8", "multicast address"),
	pfx("2001:db8::/32", "documentation address"),
}

var loopbackPrefixes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

var (
	sixToFour = netip.MustParsePrefix("2002::/16")
	siit      = netip.MustParsePrefix("::ffff:0:0:0/96")
	teredo    = netip.MustParsePrefix("2001::/32")
)

// Classify returns the class of a and, for forbidden addresses, why.
func Classify(a netip.Addr) (Class, string) {
	if !a.IsValid() {
		return Forbidden, "invalid address"
	}
	a = a.WithZone("").Unmap()
	for _, m := range metadataAddrs {
		if a == m {
			return Forbidden, "cloud metadata address"
		}
	}
	// Loopback first: ::1 also sits inside the deprecated ::/96 range.
	for _, p := range loopbackPrefixes {
		if p.Contains(a) {
			return Loopback, ""
		}
	}
	for _, f := range forbiddenPrefixes {
		if f.p.Contains(a) {
			return Forbidden, f.reason
		}
	}
	// Embedded IPv4 forms are checked after the outer address, so an
	// interface ID that looks like ISATAP cannot hide a forbidden range.
	if v4, ok := embeddedIPv4(a); ok {
		c, reason := Classify(v4)
		switch c {
		case Forbidden:
			return Forbidden, reason + " behind an IPv6 translation prefix"
		case Loopback, Private:
			return Forbidden, "translated local address"
		}
		return Public, ""
	}
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return Private, ""
		}
	}
	return Public, ""
}

// defaultNAT64 are the well-known (RFC 6052) and local-use (RFC 8215)
// prefixes; a network-specific prefix can be added with SetNAT64Prefixes.
var defaultNAT64 = []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48")}

var nat64Prefixes atomic.Pointer[[]netip.Prefix]

func init() { _ = SetNAT64Prefixes(nil) }

// rfc6052Bytes lists, per prefix length, the address bytes that hold the
// embedded IPv4 address (byte 8 is reserved and skipped).
var rfc6052Bytes = map[int][4]int{
	32: {4, 5, 6, 7}, 40: {5, 6, 7, 9}, 48: {6, 7, 9, 10},
	56: {7, 9, 10, 11}, 64: {9, 10, 11, 12}, 96: {12, 13, 14, 15},
}

// SetNAT64Prefixes adds network-specific NAT64 prefixes to the well-known
// ones. Lengths must be 32, 40, 48, 56, 64 or 96.
func SetNAT64Prefixes(extra []netip.Prefix) error {
	all := append([]netip.Prefix(nil), defaultNAT64...)
	for _, p := range extra {
		if _, ok := rfc6052Bytes[p.Bits()]; !ok || !p.Addr().Is6() || p.Addr().Is4In6() {
			return fmt.Errorf("NAT64 prefix %s: need an IPv6 prefix of length 32, 40, 48, 56, 64 or 96", p)
		}
		all = append(all, p.Masked())
	}
	nat64Prefixes.Store(&all)
	return nil
}

// embeddedIPv4 extracts the IPv4 address from NAT64, SIIT, 6to4, Teredo
// (the obfuscated client address) and ISATAP forms.
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	best := -1
	for _, p := range *nat64Prefixes.Load() {
		if p.Contains(a) && p.Bits() > best {
			best = p.Bits()
		}
	}
	if best >= 0 {
		pos := rfc6052Bytes[best]
		return netip.AddrFrom4([4]byte{b[pos[0]], b[pos[1]], b[pos[2]], b[pos[3]]}), true
	}
	switch {
	case siit.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case teredo.Contains(a):
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	case (b[8]|0x02) == 0x02 && b[9] == 0 && b[10] == 0x5e && b[11] == 0xfe:
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}
