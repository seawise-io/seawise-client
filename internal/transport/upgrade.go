package transport

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // G505: RFC 6455 fixes SHA-1 for the accept value
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// maxUpgradeResponse bounds the status line and headers of the answer.
	maxUpgradeResponse = 4096
)

var errUpgradeTooLarge = errors.New("upgrade response over 4096 bytes")

// upgradeRequest is the one HTTP request sent on the WebSocket carriage.
func upgradeRequest(name, key string) []byte {
	return []byte("GET " + wire.WebSocketPath + " HTTP/1.1\r\n" +
		"Host: " + name + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Protocol: " + wire.WebSocketProtocol + "\r\n\r\n")
}

func acceptValue(key string) string {
	h := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // G401: RFC 6455
	return base64.StdEncoding.EncodeToString(h[:])
}

// readUpgradeResponse reads the answer to the upgrade request and returns
// the bytes read past its header block, which start the edge's frames.
func readUpgradeResponse(r io.Reader, key string) ([]byte, error) {
	buf := make([]byte, maxUpgradeResponse)
	n := 0
	for {
		if i := bytes.Index(buf[:n], []byte("\r\n\r\n")); i >= 0 {
			if err := checkUpgradeResponse(buf[:i+4], key); err != nil {
				return nil, err
			}
			return bytes.Clone(buf[i+4 : n]), nil
		}
		if n == len(buf) {
			return nil, blocked(CauseTLS, "upgrade", errUpgradeTooLarge)
		}
		m, err := r.Read(buf[n:])
		n += m
		if err != nil && m == 0 {
			return nil, blocked(CauseTLS, "upgrade_io", err)
		}
	}
}

// checkUpgradeResponse checks a header block ending in CRLF CRLF. Only a
// 426 or a 101 without the subprotocol is a subprotocol refusal; any other
// failure is a broken upgrade.
func checkUpgradeResponse(b []byte, key string) error {
	bad := func(what string) error { return blocked(CauseTLS, "upgrade", errors.New("upgrade response: "+what)) }
	lines := strings.Split(string(b[:len(b)-4]), "\r\n")
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return bad("bare CR or LF")
		}
	}
	code, ok := statusCode(lines[0])
	if !ok {
		return bad("status line")
	}
	if code == "426" {
		return blocked(CauseSubprotocol, "upgrade_426", errors.New("edge has no common subprotocol"))
	}
	if code != "101" {
		return bad("status " + code)
	}
	h := map[string][]string{}
	for _, l := range lines[1:] {
		name, value, ok := headerLine(l)
		if !ok {
			return bad("header line")
		}
		h[name] = append(h[name], value)
	}
	if v := h["upgrade"]; len(v) != 1 || !strings.EqualFold(v[0], "websocket") {
		return bad("upgrade header")
	}
	if !hasToken(h["connection"], "upgrade") {
		return bad("connection header")
	}
	if v := h["sec-websocket-accept"]; len(v) != 1 || v[0] != acceptValue(key) {
		return bad("accept value")
	}
	if len(h["sec-websocket-extensions"]) != 0 {
		return bad("extensions")
	}
	switch v := h["sec-websocket-protocol"]; {
	case len(v) == 0:
		return blocked(CauseSubprotocol, "upgrade_no_subprotocol", errors.New("edge selected no subprotocol"))
	case len(v) != 1 || v[0] != wire.WebSocketProtocol:
		return bad("subprotocol")
	}
	return nil
}

// statusCode parses "HTTP/1.1 SP 3DIGIT SP reason".
func statusCode(l string) (string, bool) {
	rest, ok := strings.CutPrefix(l, "HTTP/1.1 ")
	if !ok || len(rest) < 4 || rest[3] != ' ' {
		return "", false
	}
	code := rest[:3]
	for i := range 3 {
		if code[i] < '0' || code[i] > '9' {
			return "", false
		}
	}
	for _, c := range []byte(rest[4:]) {
		if c != '\t' && (c < 0x20 || c == 0x7f) {
			return "", false
		}
	}
	return code, true
}

// headerLine parses token ":" OWS value OWS; the name is lower-cased.
func headerLine(l string) (string, string, bool) {
	name, value, ok := strings.Cut(l, ":")
	if !ok || name == "" {
		return "", "", false
	}
	for _, c := range []byte(name) {
		if !isTchar(c) {
			return "", "", false
		}
	}
	for _, c := range []byte(value) {
		if c != '\t' && (c < 0x20 || c == 0x7f) {
			return "", "", false
		}
	}
	return strings.ToLower(name), strings.Trim(value, " \t"), true
}

func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func hasToken(values []string, token string) bool {
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.Trim(t, " \t"), token) {
				return true
			}
		}
	}
	return false
}
