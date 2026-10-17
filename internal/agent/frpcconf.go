package agent

import (
	"fmt"
	"math"
	"net/netip"
	"strings"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

type desired struct {
	// serverAddr is what frpc dials: the host name, or a cached address
	// when DNS fails. tlsName is always the host name.
	serverAddr   string
	tlsName      string
	serverPort   int
	proxyURL     string
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

// tomlEscape makes s safe inside a TOML basic string: quotes, backslashes
// and every control character are escaped.
func tomlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// renderCommon returns the part of frpc.toml that needs a process restart
// when it changes; renderProxies is hot-reloadable.
func (d *desired) renderCommon() string {
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = \"%s\"\nserverPort = %d\n", tomlEscape(d.serverAddr), d.serverPort)
	fmt.Fprintf(&b, "transport.tls.enable = true\ntransport.tls.serverName = \"%s\"\ntransport.tls.trustedCaFile = \"%s\"\n",
		tomlEscape(d.tlsName), tomlEscape(d.trustedCA))
	if d.proxyURL != "" {
		fmt.Fprintf(&b, "transport.proxyURL = \"%s\"\n", tomlEscape(d.proxyURL))
	}
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
// confirmed locally (or grandfathered), not public on the server unless the
// owner made them public here, and, where the address is known
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
		if t.ServerPublic && !t.IsPublicLocally() {
			refused = append(refused, RefusedApp{LocalID: t.LocalID, Reason: "public on SeaWise but private on this machine"})
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

func allowedServer(addr string, allowed []string) bool {
	addr = strings.ToLower(addr)
	for _, a := range allowed {
		if addr == strings.TrimPrefix(a, ".") || (strings.HasPrefix(a, ".") && strings.HasSuffix(addr, a)) || addr == a {
			return true
		}
	}
	return false
}
