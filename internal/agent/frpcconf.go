package agent

import (
	"fmt"
	"strings"

	"github.com/seawise/client/internal/store"
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
	targets      []store.Target
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
	for _, t := range d.targets {
		fmt.Fprintf(&b, "\n[[proxies]]\nname = \"%s-%s\"\ntype = \"http\"\nlocalIP = \"%s\"\nlocalPort = %d\nsubdomain = \"%s\"\n",
			tomlEscape(d.serverID), tomlEscape(t.Name), tomlEscape(t.Host), t.Port, tomlEscape(t.Subdomain))
	}
	return b.String()
}

// tunnelled mirrors v1: enabled targets that have a registered subdomain.
func tunnelled(targets []store.Target) []store.Target {
	out := make([]store.Target, 0, len(targets))
	for _, t := range targets {
		if t.Disabled || t.Subdomain == "" {
			continue
		}
		out = append(out, t)
	}
	return out
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
