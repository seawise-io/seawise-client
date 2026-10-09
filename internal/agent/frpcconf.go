package agent

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

type desired struct {
	serverAddr   string
	serverPort   int
	token        string
	serverID     string
	connectionID string
	adminHost    string
	adminPort    int
	adminUser    string
	adminPass    string
	trustedCA    string
	proxies      []proxyEntry
}

type proxyEntry struct {
	name      string
	subdomain string
	port      int
}

func tomlEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
}

// renderCommon returns the part of frpc.toml that needs a process restart
// when it changes; renderProxies is hot-reloadable.
func (d *desired) renderCommon() string {
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = \"%s\"\nserverPort = %d\n", tomlEscape(d.serverAddr), d.serverPort)
	fmt.Fprintf(&b, "transport.tls.enable = true\ntransport.tls.serverName = \"%s\"\ntransport.tls.trustedCaFile = \"%s\"\n",
		tomlEscape(d.serverAddr), tomlEscape(d.trustedCA))
	fmt.Fprintf(&b, "metadatas.token = \"%s\"\nmetadatas.server_id = \"%s\"\nmetadatas.connection_id = \"%s\"\n",
		tomlEscape(d.token), tomlEscape(d.serverID), tomlEscape(d.connectionID))
	fmt.Fprintf(&b, "webServer.addr = \"%s\"\nwebServer.port = %d\nwebServer.user = \"%s\"\nwebServer.password = \"%s\"\n",
		tomlEscape(d.adminHost), d.adminPort, tomlEscape(d.adminUser), tomlEscape(d.adminPass))
	b.WriteString("log.to = \"console\"\nlog.level = \"info\"\n")
	return b.String()
}

func (d *desired) renderProxies() string {
	var b strings.Builder
	for _, p := range d.proxies {
		fmt.Fprintf(&b, "\n[[proxies]]\nname = \"%s-%s\"\ntype = \"http\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nsubdomain = \"%s\"\n",
			tomlEscape(d.serverID), tomlEscape(p.name), p.port, tomlEscape(p.subdomain))
	}
	return b.String()
}

// admit returns the targets that may be tunnelled: enabled, registered,
// confirmed locally (or grandfathered), and, where the address is known
// without DNS, accepted by the target policy. Names are checked again on
// every connection by the forwarder.
func admit(targets []store.Target, gateways []netip.Addr) ([]store.Target, []RefusedApp) {
	out := make([]store.Target, 0, len(targets))
	var refused []RefusedApp
	for _, t := range targets {
		if t.Disabled || t.Subdomain == "" {
			continue
		}
		if !t.Grandfathered && t.ConfirmedAt == nil {
			refused = append(refused, RefusedApp{LocalID: t.LocalID, Reason: "not confirmed on this machine"})
			continue
		}
		if addr, ok := literal(t.Host); ok {
			if err := targetpolicy.Check(targetpolicy.RuleFor(t), netip.AddrPortFrom(addr, uint16(t.Port)), gateways); err != nil {
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

func allowedServer(addr string, allowed []string) bool {
	addr = strings.ToLower(addr)
	for _, a := range allowed {
		if addr == strings.TrimPrefix(a, ".") || (strings.HasPrefix(a, ".") && strings.HasSuffix(addr, a)) || addr == a {
			return true
		}
	}
	return false
}
