package targetpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"169.254.169.254": Forbidden, "fd00:ec2::254": Forbidden, "100.100.100.200": Forbidden, "192.0.0.192": Forbidden,
		"169.254.1.1": Forbidden, "fe80::1": Forbidden, "fe80::1%eth0": Forbidden,
		"0.0.0.0": Forbidden, "::": Forbidden, "255.255.255.255": Forbidden, "224.0.0.1": Forbidden, "ff02::1": Forbidden,
		"240.0.0.1": Forbidden, "192.0.2.1": Forbidden, "198.18.0.1": Forbidden, "::127.0.0.1": Forbidden, "fec0::1": Forbidden,
		"::ffff:169.254.169.254":   Forbidden,
		"64:ff9b::a9fe:a9fe":       Forbidden, // NAT64 of metadata
		"64:ff9b::7f00:1":          Forbidden, // NAT64 of loopback
		"64:ff9b::c0a8:101":        Forbidden, // NAT64 of private
		"2002:a9fe:a9fe::1":        Forbidden, // 6to4 of metadata
		"2002:c0a8:0101::1":        Forbidden, // 6to4 of private
		"64:ff9b::808:808":         Public,
		"64:ff9b:1:a9fe:a9:fe00::": Forbidden,
		"127.0.0.1":                Loopback, "127.1.2.3": Loopback, "::1": Loopback, "::ffff:127.0.0.1": Loopback,
		"10.0.0.1": Private, "172.16.5.4": Private, "172.31.255.255": Private, "192.168.1.1": Private,
		"100.64.0.1": Private, "100.127.255.254": Private, "fd12:3456::1": Private, "::ffff:192.168.1.5": Private,
		"172.32.0.1": Public, "8.8.8.8": Public, "2606:4700::1111": Public, "100.128.0.1": Public, "11.0.0.1": Public,
	}
	for s, want := range cases {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(s, err)
		}
		if got, reason := Classify(a); got != want || (got == Forbidden && reason == "") {
			t.Errorf("%s: %s %q want %s", s, got, reason, want)
		}
	}
	if c, _ := Classify(netip.Addr{}); c != Forbidden {
		t.Fatal("invalid address not forbidden")
	}
}

func ap(s string, port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(s), uint16(port))
}

// Only forbidden addresses are refused; every other class is reachable, as
// with 1.x, and only described for the review list.
func TestCheckClasses(t *testing.T) {
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	cases := []struct {
		name string
		rule Rule
		addr netip.AddrPort
		ok   bool
	}{
		{"private", Rule{Host: "nas.lan"}, ap("192.168.1.20", 8096), true},
		{"metadata", Rule{Host: "169.254.169.254"}, ap("169.254.169.254", 80), false},
		{"link-local", Rule{Host: "x"}, ap("169.254.10.10", 80), false},
		{"multicast", Rule{Host: "x"}, ap("224.0.0.1", 80), false},
		{"public", Rule{Host: "example.com"}, ap("93.184.216.34", 443), true},
		{"public smtp", Rule{Host: "mail.example"}, ap("93.184.216.34", 25), true},
		{"docker api", Rule{Host: "nas.lan"}, ap("192.168.1.20", 2375), true},
		{"router", Rule{Host: "192.168.1.1"}, ap("192.168.1.1", 80), true},
		{"loopback", Rule{Host: "localhost"}, ap("127.0.0.1", 3000), true},
		{"name resolving to loopback", Rule{Host: "app.example"}, ap("127.0.0.1", 3000), true},
		{"loopback docker api", Rule{Host: "localhost"}, ap("127.0.0.1", 2375), true},
	}
	for _, c := range cases {
		err := Check(c.rule, c.addr, gw)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && !errors.Is(err, ErrRefused) {
			t.Errorf("%s: error not ErrRefused", c.name)
		}
	}
}

func TestAssessNewApps(t *testing.T) {
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	addrs := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, x := range s {
			out = append(out, netip.MustParseAddr(x))
		}
		return out
	}
	as := Assess("nas.lan", 8096, addrs("192.168.1.20"), gw)
	if as.Refused != "" || len(as.Required) != 0 {
		t.Fatalf("private: %+v", as)
	}
	as = Assess("example.com", 443, addrs("93.184.216.34"), gw)
	if as.Refused != "" || !reflect.DeepEqual(as.Required, []string{GrantPublic}) {
		t.Fatalf("public is described, not refused: %+v", as)
	}
	as = Assess("mixed.lan", 80, addrs("192.168.1.20", "169.254.169.254"), gw)
	if as.Refused == "" {
		t.Fatalf("one forbidden address must refuse: %+v", as)
	}
	if as := Assess("nas.lan", 80, nil, gw); as.Refused == "" {
		t.Fatal("unresolved accepted")
	}
	if as := Assess("nas.lan", 0, addrs("192.168.1.20"), gw); as.Refused == "" {
		t.Fatal("invalid port accepted")
	}
	as = Assess("localhost", 2375, addrs("127.0.0.1", "::1"), gw)
	if as.Refused != "" || !reflect.DeepEqual(as.Required, []string{GrantLoopback, GrantSensitive}) {
		t.Fatalf("loopback docker: %+v", as)
	}
}

// TestDialer dials through the Control hook: the check runs on the address
// actually connected to, whatever the name resolved to.
func TestDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, host := range []string{"localhost", "app.example"} {
		c, err := Dialer(&net.Dialer{Timeout: time.Second}, Rule{Host: host}, nil).DialContext(ctx, "tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Fatalf("%s: loopback refused: %v", host, err)
		}
		c.Close()
	}
	meta := Dialer(nil, Rule{Host: "nas.lan"}, nil)
	if _, err := meta.DialContext(ctx, "tcp", "169.254.169.254:80"); !errors.Is(err, ErrRefused) {
		t.Fatalf("metadata not refused before connect: %v", err)
	}
}

func TestDialerKeepsBaseControl(t *testing.T) {
	called := 0
	base := &net.Dialer{Timeout: time.Second, Control: func(string, string, syscall.RawConn) error { called++; return nil }}
	d := Dialer(base, Rule{Host: "nas.lan"}, nil)
	ctx := context.Background()
	if _, err := d.DialContext(ctx, "tcp", "169.254.169.254:80"); !errors.Is(err, ErrRefused) || called != 0 {
		t.Fatalf("refused dial reached base control: %v %d", err, called)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d = Dialer(base, Rule{Host: "127.0.0.1"}, nil)
	c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil || called != 1 {
		t.Fatalf("base control not chained: %v %d", err, called)
	}
	c.Close()
}

// The review list is informational: it names what an app reaches, apps that
// are turned off and refused addresses; nothing in it needs a confirmation.
func TestReviewList(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	targets := []store.Target{
		{LocalID: "a", Name: "plex", Host: "192.168.1.20", Port: 32400, Grandfathered: true, Source: store.SourceV1Machine, ConfirmedAt: &now},
		{LocalID: "b", Name: "site", Host: "example.com", Port: 443, Source: store.SourceLocal},
		{LocalID: "c", Name: "meta", Host: "169.254.169.254", Port: 80, Source: store.SourceV1Machine},
		{LocalID: "d", Name: "new", Host: "192.168.1.30", Port: 80, Source: store.SourceLocal},
		{LocalID: "e", Name: "gone", Host: "nowhere.lan", Port: 80, Source: store.SourceLocal},
		{LocalID: "f", Name: "off", Host: "192.168.1.31", Port: 80, Source: store.SourceLocal, Disabled: true},
		{LocalID: "g", Name: "asked", Host: "192.168.1.32", Port: 80, Source: store.SourceLocal, ServerDisableRequestedAt: &now},
	}
	resolve := func(_ context.Context, h string) ([]netip.Addr, error) {
		if h == "example.com" {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	items := BuildReview(context.Background(), targets, resolve, nil)
	byID := map[string]ReviewItem{}
	for _, it := range items {
		byID[it.LocalID] = it
	}
	if len(items) != 5 || byID["a"].LocalID != "" || byID["d"].LocalID != "" {
		t.Fatalf("items %+v", items)
	}
	if !reflect.DeepEqual(byID["b"].Required, []string{GrantPublic}) || byID["b"].Refused != "" {
		t.Fatalf("public %+v", byID["b"])
	}
	if byID["c"].Refused == "" || byID["e"].Refused != "host did not resolve" || !byID["f"].Disabled || byID["g"].ServerDisableRequestedAt == nil {
		t.Fatalf("items %+v", items)
	}
	st := store.State{Targets: targets}
	if err := Disable(&st, "c"); err != nil || !st.Targets[2].Disabled || len(st.Targets) != 7 {
		t.Fatal("disable")
	}
	if Disable(&st, "zz") != ErrNotFound {
		t.Fatal("unknown id")
	}
}

func TestParseRoutes(t *testing.T) {
	v4 := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\nmeth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\neth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
	if got := parseIPv4Routes([]byte(v4)); len(got) != 1 || got[0] != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("v4 %v", got)
	}
	v6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" +
		"fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
	if got := parseIPv6Routes([]byte(v6)); len(got) != 1 || got[0] != netip.MustParseAddr("fe80::1") {
		t.Fatalf("v6 %v", got)
	}
}

func TestClassifyTranslationForms(t *testing.T) {
	cases := map[string]Class{
		"::ffff:0:a9fe:a9fe":                   Forbidden, // SIIT metadata
		"::ffff:0:7f00:1":                      Forbidden, // SIIT loopback
		"::ffff:0:c0a8:101":                    Forbidden, // SIIT private
		"::ffff:0:808:808":                     Public,
		"2001:0:4136:e378:8000:63bf:5601:5601": Forbidden, // Teredo, client 169.254.169.254 (xor ff)
		"2001:0:4136:e378:8000:63bf:f5ff:fefe": Forbidden, // Teredo, client 10.0.1.1
		"2001:0:4136:e378:8000:63bf:f7f7:f7f7": Public,    // Teredo, client 8.8.8.8
		"fd00::5efe:a9fe:a9fe":                 Forbidden, // ISATAP metadata
		"2001:db9::200:5efe:7f00:1":            Forbidden, // ISATAP loopback
		"2606:4700::5efe:808:808":              Public,
		"ff30:3030:3030:3030:0:5efe:3030:3030": Forbidden, // multicast with an ISATAP-like interface ID
		"fe80::5efe:808:808":                   Forbidden,
	}
	for s, want := range cases {
		if got, _ := Classify(netip.MustParseAddr(s)); got != want {
			t.Errorf("%s: %s want %s", s, got, want)
		}
	}
}

func TestGatewayDescribed(t *testing.T) {
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	if err := Check(Rule{Host: "192.168.1.1"}, ap("192.168.1.1", 80), gw); err != nil {
		t.Fatalf("router refused: %v", err)
	}
	as := Assess("192.168.1.1", 80, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, gw)
	if !reflect.DeepEqual(as.Required, []string{GrantGateway}) {
		t.Fatalf("gateway: %+v", as)
	}
}

func TestPublicSensitivePortDescribed(t *testing.T) {
	for _, port := range []int{2375, 2376, 6443, 10250, 10255, 2379, 2380} {
		if err := Check(Rule{Host: "203.0.114.9"}, ap("203.0.114.9", port), nil); err != nil {
			t.Errorf("public port %d refused: %v", port, err)
		}
	}
	as := Assess("203.0.114.9", 2375, []netip.Addr{netip.MustParseAddr("203.0.114.9")}, nil)
	if !reflect.DeepEqual(as.Required, []string{GrantPublic, GrantSensitive}) || !slices.Contains(as.Reasons, "Docker API") {
		t.Fatalf("assessment does not name the port: %+v", as)
	}
}

func TestMoreMetadataAddresses(t *testing.T) {
	for _, s := range []string{"168.63.129.16", "fd20:ce::254", "fd00:ec2::254", "::ffff:168.63.129.16"} {
		if c, reason := Classify(netip.MustParseAddr(s)); c != Forbidden || reason != "cloud metadata address" {
			t.Errorf("%s: %s %q", s, c, reason)
		}
	}
}

// embed builds an RFC 6052 address for v4 under prefix p.
func embed(p netip.Prefix, v4 netip.Addr) netip.Addr {
	b := p.Addr().As16()
	v := v4.As4()
	pos := map[int][]int{32: {4, 5, 6, 7}, 40: {5, 6, 7, 9}, 48: {6, 7, 9, 10}, 56: {7, 9, 10, 11}, 64: {9, 10, 11, 12}, 96: {12, 13, 14, 15}}[p.Bits()]
	for i, j := range pos {
		b[j] = v[i]
	}
	return netip.AddrFrom16(b)
}

func TestNAT64AllPrefixLengths(t *testing.T) {
	defer SetNAT64Prefixes(nil)
	var prefixes []netip.Prefix
	for _, s := range []string{"2001:db9::/32", "2001:db9:100::/40", "2001:db9:200::/48", "2001:db9:300::/56", "2001:db9:400::/64", "2001:db9:500::/96"} {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	if err := SetNAT64Prefixes(prefixes); err != nil {
		t.Fatal(err)
	}
	for _, p := range prefixes {
		for v4, want := range map[string]Class{"169.254.169.254": Forbidden, "10.0.0.1": Forbidden, "127.0.0.1": Forbidden, "8.8.8.8": Public} {
			a := embed(p, netip.MustParseAddr(v4))
			if got, _ := Classify(a); got != want {
				t.Errorf("%s (%s in %s): %s want %s", a, v4, p, got, want)
			}
		}
	}
	if err := SetNAT64Prefixes([]netip.Prefix{netip.MustParsePrefix("2001:db9::/44")}); err == nil {
		t.Fatal("invalid prefix length accepted")
	}
	if err := SetNAT64Prefixes([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err == nil {
		t.Fatal("IPv4 prefix accepted")
	}
}
