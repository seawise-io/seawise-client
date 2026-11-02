package agent

import (
	"math"
	"net/netip"
	"strings"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

// admit returns the targets that may be tunnelled: enabled, registered, and,
// where the address is known without DNS, accepted by the target policy.
// Names are checked again on every connection by the forwarder.
func admit(targets []store.Target, gateways []netip.Addr) ([]store.Target, []RefusedApp) {
	out := make([]store.Target, 0, len(targets))
	var refused []RefusedApp
	for _, t := range targets {
		if t.Disabled || t.Subdomain == "" {
			continue
		}
		port := t.Port
		if port < 1 || port > math.MaxUint16 {
			refused = append(refused, RefusedApp{LocalID: t.LocalID, Reason: "invalid port"})
			continue
		}
		if addr, ok := literal(t.Host); ok {
			if err := targetpolicy.Check(targetpolicy.RuleFor(t), netip.AddrPortFrom(addr, uint16(port)), gateways); err != nil {
				refused = append(refused, RefusedApp{LocalID: t.LocalID, Reason: err.Error()})
				continue
			}
		}
		out = append(out, t)
	}
	return out, refused
}

func literal(host string) (netip.Addr, bool) {
	h := strings.Trim(host, "[]")
	if strings.EqualFold(strings.TrimSuffix(h, "."), "localhost") {
		return netip.MustParseAddr("127.0.0.1"), true
	}
	a, err := netip.ParseAddr(h)
	return a, err == nil
}
