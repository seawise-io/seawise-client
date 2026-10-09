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

func TestCheckClasses(t *testing.T) {
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	cases := []struct {
		name string
		rule Rule
		addr netip.AddrPort
		ok   bool
	}{
		{"private", Rule{Host: "nas.lan"}, ap("192.168.1.20", 8096), true},
		{"metadata even grandfathered", Rule{Host: "169.254.169.254", Grandfathered: true}, ap("169.254.169.254", 80), false},
		{"link-local even grandfathered", Rule{Host: "x", Grandfathered: true}, ap("169.254.10.10", 80), false},
		{"public without grant", Rule{Host: "example.com"}, ap("93.184.216.34", 443), false},
		{"public with grant", Rule{Host: "example.com", Grants: []string{GrantPublic}}, ap("93.184.216.34", 443), true},
		{"public smtp needs smtp", Rule{Host: "mail.example", Grants: []string{GrantPublic}}, ap("93.184.216.34", 25), false},
		{"public smtp granted", Rule{Host: "mail.example", Grants: []string{GrantPublic, GrantSMTP}}, ap("93.184.216.34", 587), true},
		{"grandfathered public", Rule{Host: "example.com", Grandfathered: true}, ap("93.184.216.34", 443), true},
		{"docker api", Rule{Host: "nas.lan"}, ap("192.168.1.20", 2375), false},
		{"docker api granted", Rule{Host: "nas.lan", Grants: []string{GrantSensitive}}, ap("192.168.1.20", 2375), true},
		{"router", Rule{Host: "192.168.1.1"}, ap("192.168.1.1", 80), false},
		{"router granted", Rule{Host: "192.168.1.1", Grants: []string{GrantGateway}}, ap("192.168.1.1", 80), true},
		{"intended loopback needs grant", Rule{Host: "localhost"}, ap("127.0.0.1", 3000), false},
		{"intended loopback granted", Rule{Host: "localhost", Grants: []string{GrantLoopback}}, ap("127.0.0.1", 3000), true},
		{"literal loopback granted", Rule{Host: "127.0.0.1", Grants: []string{GrantLoopback}}, ap("127.0.0.1", 3000), true},
		{"name rebinding to loopback", Rule{Host: "app.example", Grants: []string{GrantLoopback, GrantPublic}}, ap("127.0.0.1", 3000), false},
		{"grandfathered name to loopback", Rule{Host: "nas.lan", Grandfathered: true}, ap("127.0.0.1", 3000), false},
		{"loopback docker api", Rule{Host: "localhost", Grants: []string{GrantLoopback}}, ap("127.0.0.1", 2375), false},
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
	as := Assess("nas.lan", 8096, addrs("192.168.1.20"), gw, Options{})
	if as.Refused != "" || len(as.Required) != 0 {
		t.Fatalf("private: %+v", as)
	}
	as = Assess("example.com", 443, addrs("93.184.216.34"), gw, Options{})
	if as.Refused == "" {
		t.Fatalf("public allowed by default: %+v", as)
	}
	as = Assess("example.com", 443, addrs("93.184.216.34"), gw, Options{PublicAllowed: true})
	if as.Refused != "" || !reflect.DeepEqual(as.Required, []string{GrantPublic}) {
		t.Fatalf("public opt-in: %+v", as)
	}
	as = Assess("mixed.lan", 80, addrs("192.168.1.20", "169.254.169.254"), gw, Options{PublicAllowed: true})
	if as.Refused == "" {
		t.Fatalf("one forbidden address must refuse: %+v", as)
	}
	as = Assess("nas.lan", 80, nil, gw, Options{})
	if as.Refused == "" {
		t.Fatal("unresolved accepted")
	}
	as = Assess("localhost", 2375, addrs("127.0.0.1", "::1"), gw, Options{})
	if as.Refused != "" || !reflect.DeepEqual(as.Required, []string{GrantLoopback, GrantSensitive}) {
		t.Fatalf("loopback docker: %+v", as)
	}
}

// TestDialerRebinding dials through the Control hook: the check runs on the
// address actually connected to, whatever the name resolved to.
func TestDialerRebinding(t *testing.T) {
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

	ok := Dialer(&net.Dialer{Timeout: time.Second}, Rule{Host: "localhost", Grants: []string{GrantLoopback}}, nil)
	c, err := ok.DialContext(ctx, "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("intended loopback refused: %v", err)
	}
	c.Close()

	// A target named something else that resolves to loopback is refused at
	// connect time, even with every grant.
	rebound := Dialer(nil, Rule{Host: "app.example", Grants: []string{GrantLoopback, GrantPublic, GrantSensitive}}, nil)
	if _, err := rebound.DialContext(ctx, "tcp", "127.0.0.1:"+port); !errors.Is(err, ErrRefused) {
		t.Fatalf("rebinding not refused: %v", err)
	}
	gf := Dialer(nil, Rule{Host: "nas.lan", Grandfathered: true}, nil)
	if _, err := gf.DialContext(ctx, "tcp", "127.0.0.1:"+port); !errors.Is(err, ErrRefused) {
		t.Fatalf("grandfathered rebinding not refused: %v", err)
	}
	meta := Dialer(nil, Rule{Host: "nas.lan", Grandfathered: true}, nil)
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
	d = Dialer(base, Rule{Host: "127.0.0.1", Grants: []string{GrantLoopback}}, nil)
	c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil || called != 1 {
		t.Fatalf("base control not chained: %v %d", err, called)
	}
	c.Close()
}

func TestGrandfatheredReview(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	targets := []store.Target{
		{LocalID: "a", Name: "plex", Host: "192.168.1.20", Port: 32400, Grandfathered: true, Source: store.SourceV1Machine, ConfirmedAt: &now},
		{LocalID: "b", Name: "site", Host: "example.com", Port: 443, Grandfathered: true, Source: store.SourceV1Machine},
		{LocalID: "c", Name: "meta", Host: "169.254.169.254", Port: 80, Grandfathered: true, Source: store.SourceV1Machine},
		{LocalID: "d", Name: "new", Host: "192.168.1.30", Port: 80, Source: store.SourceLocal},
		{LocalID: "e", Name: "moved", Host: "app.lan", Port: 80, Source: store.SourceLocal},
	}
	resolve := func(_ context.Context, h string) ([]netip.Addr, error) {
		switch h {
		case "example.com":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		case "app.lan":
			return []netip.Addr{netip.MustParseAddr("93.184.216.35")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	items := BuildReview(context.Background(), targets, resolve, nil, true)
	byID := map[string]ReviewItem{}
	for _, it := range items {
		byID[it.LocalID] = it
	}
	if len(items) != 4 || byID["d"].LocalID != "" {
		t.Fatalf("items %+v", items)
	}
	if !reflect.DeepEqual(byID["b"].Required, []string{GrantPublic}) || byID["b"].Refused != "" {
		t.Fatalf("public grandfathered %+v", byID["b"])
	}
	if byID["c"].Refused == "" {
		t.Fatal("metadata target not flagged")
	}
	if !reflect.DeepEqual(byID["e"].Missing, []string{GrantPublic}) {
		t.Fatalf("non-grandfathered drift %+v", byID["e"])
	}

	st := store.State{Targets: targets}
	if err := Confirm(&st, "b", "example.com", 443, byID["b"].Assessment, now); err != nil {
		t.Fatal(err)
	}
	b := st.Targets[1]
	if b.Grandfathered || !reflect.DeepEqual(b.Allowed, []string{GrantPublic}) || b.ConfirmedAt == nil {
		t.Fatalf("confirm %+v", b)
	}
	if err := Check(RuleFor(b), ap("93.184.216.34", 443), nil); err != nil {
		t.Fatalf("confirmed target refused: %v", err)
	}
	if err := Check(RuleFor(b), ap("93.184.216.34", 25), nil); err == nil {
		t.Fatal("confirmed grants widened to smtp")
	}
	if err := Confirm(&st, "c", "169.254.169.254", 80, byID["c"].Assessment, now); err == nil {
		t.Fatal("forbidden target confirmed")
	}
	if err := Disable(&st, "c"); err != nil || !st.Targets[2].Disabled || len(st.Targets) != 5 {
		t.Fatal("disable")
	}
	if err := Confirm(&st, "a", "192.168.1.99", 32400, Assessment{Required: []string{}}, now); err != ErrChanged {
		t.Fatalf("changed target confirmed: %v", err)
	}
	if items := BuildReview(context.Background(), st.Targets, resolve, nil, false); len(items) == 0 {
		t.Fatal("disabled target not listed for re-enable")
	}
	if Confirm(&st, "zz", "h", 1, Assessment{}, now) != ErrNotFound || Disable(&st, "zz") != ErrNotFound {
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

func TestGrandfatheredNoImplicitSensitivePort(t *testing.T) {
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	gf := Rule{Host: "nas.lan", Grandfathered: true}
	if err := Check(gf, ap("192.168.1.20", 2375), gw); err == nil {
		t.Fatal("grandfathered Docker API port allowed without review")
	}
	if err := Check(gf, ap("192.168.1.1", 80), gw); err != nil {
		t.Fatalf("grandfathered router refused: %v", err)
	}
	if err := Check(gf, ap("93.184.216.34", 443), gw); err != nil {
		t.Fatalf("grandfathered public refused: %v", err)
	}
	as := Assess("192.168.1.1", 80, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, gw, Options{})
	if !reflect.DeepEqual(as.Required, []string{GrantGateway}) {
		t.Fatalf("gateway grant: %+v", as)
	}
}

func TestPublicSensitivePortNeedsBothGrants(t *testing.T) {
	for _, port := range []int{2375, 2376, 6443, 10250, 10255, 2379, 2380} {
		pub := Rule{Host: "203.0.114.9", Grants: []string{GrantPublic}}
		if err := Check(pub, ap("203.0.114.9", port), nil); err == nil {
			t.Errorf("public port %d allowed with only the public grant", port)
		}
		both := Rule{Host: "203.0.114.9", Grants: []string{GrantPublic, GrantSensitive}}
		if err := Check(both, ap("203.0.114.9", port), nil); err != nil {
			t.Errorf("public port %d refused with both grants: %v", port, err)
		}
		if err := Check(Rule{Host: "x.example", Grandfathered: true}, ap("203.0.114.9", port), nil); err == nil {
			t.Errorf("grandfathered public port %d allowed without review", port)
		}
	}
	as := Assess("203.0.114.9", 2375, []netip.Addr{netip.MustParseAddr("203.0.114.9")}, nil, Options{PublicAllowed: true})
	if !reflect.DeepEqual(as.Required, []string{GrantPublic, GrantSensitive}) || !slices.Contains(as.Reasons, "Docker API") {
		t.Fatalf("assessment does not name the port risk: %+v", as)
	}
}
