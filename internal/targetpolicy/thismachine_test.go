package targetpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestThisMachine(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0": "127.0.0.1", "::": "::1", "[::]": "::1", "[0.0.0.0]": "127.0.0.1",
	}
	for host, want := range cases {
		a, ok := ThisMachine(host)
		if !ok || a != netip.MustParseAddr(want) {
			t.Errorf("%q: got %v %v, want %s", host, a, ok, want)
		}
	}
	for _, host := range []string{"", "0", "0.0.0.1", "0.0.0.0.", "0:0::0", "0:0:0:0:0:0:0:0", "::0", "::ffff:0.0.0.0",
		"[::", "::]", " 0.0.0.0", "0.0.0.0 ", "localhost", "127.0.0.1", "::1", "00.0.0.0", "0.0.0.0%eth0", "::%eth0"} {
		if a, ok := ThisMachine(host); ok {
			t.Errorf("%q mapped to %v", host, a)
		}
	}
}

func TestResolveHostMapsThisMachine(t *testing.T) {
	never := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("resolver called") }
	for host, want := range map[string]string{"0.0.0.0": "127.0.0.1", "::": "::1", "[::]": "::1"} {
		got, err := ResolveHost(context.Background(), never, host)
		if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr(want) {
			t.Errorf("%q: %v %v", host, got, err)
		}
	}
	zero := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil
	}
	got, err := ResolveHost(context.Background(), zero, "zero.example")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("0.0.0.0") {
		t.Fatalf("a name resolving to 0.0.0.0 must stay as is: %v %v", got, err)
	}
	if err := Check(Rule{Host: "zero.example"}, netip.AddrPortFrom(got[0], 80), nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("0.0.0.0 from DNS must stay refused: %v", err)
	}
	for _, s := range []string{"0:0::0", "::ffff:0.0.0.0", "0.0.0.1"} {
		got, err := ResolveHost(context.Background(), never, s)
		if err != nil || len(got) != 1 {
			t.Fatal(s, got, err)
		}
		if err := Check(Rule{Host: s}, netip.AddrPortFrom(got[0], 80), nil); !errors.Is(err, ErrRefused) {
			t.Errorf("%s must stay refused: %v", s, err)
		}
	}
}

func TestReviewListThisMachine(t *testing.T) {
	never := func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("resolver called") }
	as := Assess("0.0.0.0", 8096, mustResolve(t, never, "0.0.0.0"), nil)
	if as.Refused != "" || len(as.Classes) != 1 || as.Classes[0] != Loopback {
		t.Fatalf("%+v", as)
	}
}

func mustResolve(t *testing.T, r Resolver, host string) []netip.Addr {
	t.Helper()
	a, err := ResolveHost(context.Background(), r, host)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
