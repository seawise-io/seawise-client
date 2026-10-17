package agent

import (
	"strings"
	"testing"
)

func TestTOMLEscapeControlCharacters(t *testing.T) {
	var raw strings.Builder
	for c := 0; c < 0x20; c++ {
		raw.WriteByte(byte(c))
	}
	raw.WriteString("\x7f\"\\end")
	d := &desired{serverAddr: "frp-1.seawise.dev", tlsName: "frp-1.seawise.dev", serverPort: 7000, serverID: "sid",
		proxies: []proxyEntry{{name: raw.String(), subdomain: "x", port: 1}}}
	out := d.renderCommon() + d.renderProxies()
	for _, line := range strings.Split(out, "\n") {
		for _, r := range line {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("raw control character %#x in %q", r, line)
			}
		}
	}
	if !strings.Contains(out, `\u0001`) || !strings.Contains(out, `\u007f`) || !strings.Contains(out, `\"\\end`) {
		t.Fatalf("escapes missing:\n%s", out)
	}
	if got := tomlEscape("a\tb\nc"); got != `a\tb\nc` {
		t.Fatalf("common escapes: %q", got)
	}
}
