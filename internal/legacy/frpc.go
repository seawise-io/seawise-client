package legacy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FRPCConfig is the subset of a v1 frpc.toml needed to recover tunnel
// targets. The auth token is deliberately not kept.
type FRPCConfig struct {
	ServerAddr string
	ServerPort int
	ServerID   string
	Proxies    []Proxy
}

type Proxy struct {
	Name      string
	Type      string
	LocalIP   string
	LocalPort int
	Subdomain string
	E2E       bool
}

// parseFRPC understands the flat TOML that every v1 release writes: top
// level keys, [[proxies]] tables and a [proxies.plugin] sub-table.
func parseFRPC(data []byte) (*FRPCConfig, error) {
	cfg := &FRPCConfig{}
	var cur *Proxy
	section := "top"
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), MaxFileSize+1)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch line {
		case "[[proxies]]":
			if len(cfg.Proxies) >= MaxServices {
				return nil, fmt.Errorf("%w: too many proxies", ErrMalformed)
			}
			cfg.Proxies = append(cfg.Proxies, Proxy{})
			cur = &cfg.Proxies[len(cfg.Proxies)-1]
			section = "proxy"
			continue
		case "[proxies.plugin]":
			if cur == nil {
				return nil, fmt.Errorf("%w: line %d: plugin outside proxy", ErrMalformed, lineNo)
			}
			section = "plugin"
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = "other"
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: line %d: expected key = value", ErrMalformed, lineNo)
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)
		if err := cfg.set(section, cur, key, raw); err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrMalformed, lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: unreadable", ErrMalformed)
	}
	prefix := cfg.ServerID + "-"
	for i := range cfg.Proxies {
		cfg.Proxies[i].Name = strings.TrimPrefix(cfg.Proxies[i].Name, prefix)
	}
	return cfg, nil
}

func (c *FRPCConfig) set(section string, p *Proxy, key, raw string) error {
	switch section {
	case "top":
		switch key {
		case "serverAddr":
			return str(raw, &c.ServerAddr)
		case "serverPort":
			return port(raw, &c.ServerPort)
		case "metadatas.server_id":
			return str(raw, &c.ServerID)
		}
	case "proxy":
		switch key {
		case "name":
			return str(raw, &p.Name)
		case "type":
			return str(raw, &p.Type)
		case "localIP":
			return str(raw, &p.LocalIP)
		case "localPort":
			return port(raw, &p.LocalPort)
		case "subdomain":
			return str(raw, &p.Subdomain)
		}
	case "plugin":
		switch key {
		case "type":
			var t string
			if err := str(raw, &t); err != nil {
				return err
			}
			p.E2E = t == "https2http"
		case "localAddr":
			var addr string
			if err := str(raw, &addr); err != nil {
				return err
			}
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return fmt.Errorf("bad localAddr")
			}
			p.LocalIP = host
			return port(portStr, &p.LocalPort)
		case "subdomain":
			// v1 templates place subdomain after the plugin table, so TOML
			// assigns it to the plugin; frpc reads it from the proxy.
			return str(raw, &p.Subdomain)
		}
	}
	return nil
}

func port(raw string, dst *int) error {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("bad port")
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("port %d out of range", n)
	}
	*dst = n
	return nil
}

// str decodes a TOML basic string.
func str(raw string, dst *string) error {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return fmt.Errorf("expected quoted string")
	}
	body := raw[1 : len(raw)-1]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '"' {
			return fmt.Errorf("unescaped quote")
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(body) {
			return fmt.Errorf("dangling escape")
		}
		switch body[i] {
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'u', 'U':
			n := 4
			if body[i] == 'U' {
				n = 8
			}
			if i+1+n > len(body) {
				return fmt.Errorf("short unicode escape")
			}
			v, err := strconv.ParseUint(body[i+1:i+1+n], 16, 32)
			if err != nil || !utf8.ValidRune(rune(v)) {
				return fmt.Errorf("bad unicode escape")
			}
			b.WriteRune(rune(v))
			i += n
		default:
			return fmt.Errorf("unknown escape at byte %d", i)
		}
	}
	*dst = b.String()
	return nil
}
