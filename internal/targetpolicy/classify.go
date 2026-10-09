// Package targetpolicy decides which addresses an app may reach. The agent
// applies it twice: when it renders frpc's config (literal addresses and
// unconfirmed apps) and in the forwarding proxy's dialer, on the address
// actually connected to, for every connection.
package targetpolicy

import (
	"net/netip"
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
	netip.MustParseAddr("fd00:ec2::254"),
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
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	nat64Site = netip.MustParsePrefix("64:ff9b:1::/48")
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

// embeddedIPv4 extracts the IPv4 address from NAT64, SIIT, 6to4, Teredo
// (the obfuscated client address) and ISATAP forms.
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case nat64Site.Contains(a):
		// RFC 6052 /48: the IPv4 bits sit in bytes 6, 7, 9 and 10.
		return netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]}), true
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
