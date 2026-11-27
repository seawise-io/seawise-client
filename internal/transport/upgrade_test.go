package transport

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

const rfcKey = "dGhlIHNhbXBsZSBub25jZQ=="

func TestAcceptVector(t *testing.T) {
	// RFC 6455 §1.3.
	if acceptValue(rfcKey) != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal(acceptValue(rfcKey))
	}
}

func TestUpgradeRequestBytes(t *testing.T) {
	want := "GET /__seawise/tunnel HTTP/1.1\r\nHost: tunnel-us-east.seawise.dev\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + rfcKey + "\r\n" +
		"Sec-WebSocket-Protocol: sw-tunnel.1\r\n\r\n"
	if got := string(upgradeRequest(testName, rfcKey)); got != want {
		t.Fatalf("%q", got)
	}
}

func good(extra ...string) string {
	return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		acceptValue(rfcKey) + "\r\nSec-WebSocket-Protocol: sw-tunnel.1\r\n" + strings.Join(extra, "") + "\r\n"
}

func TestUpgradeResponse(t *testing.T) {
	acc := acceptValue(rfcKey)
	cases := []struct {
		name, resp string
		cause      string // "" accepted
	}{
		{"exact", good(), ""},
		{"case and spacing", "HTTP/1.1 101 OK\r\nupgrade:WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\nsec-websocket-accept:  " + acc +
			" \r\nSec-WebSocket-Protocol:\tsw-tunnel.1\r\nServer: edge\r\n\r\n", ""},
		{"empty reason", "HTTP/1.1 101 \r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acc + "\r\nSec-WebSocket-Protocol: sw-tunnel.1\r\n\r\n", ""},
		{"connection repeated", good("Connection: close\r\n"), ""},
		{"426", "HTTP/1.1 426 Upgrade Required\r\nUpgrade: websocket\r\n\r\n", CauseSubprotocol},
		{"no subprotocol", strings.Replace(good(), "Sec-WebSocket-Protocol: sw-tunnel.1\r\n", "", 1), CauseSubprotocol},
		{"other subprotocol", strings.Replace(good(), "sw-tunnel.1", "sw-tunnel.2", 1), CauseTLS},
		{"two subprotocols", good("Sec-WebSocket-Protocol: sw-tunnel.1\r\n"), CauseTLS},
		{"subprotocol list", strings.Replace(good(), "sw-tunnel.1", "sw-tunnel.1, x", 1), CauseTLS},
		{"404", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", CauseTLS},
		{"400", "HTTP/1.1 400 Bad Request\r\n\r\n", CauseTLS},
		{"200", "HTTP/1.1 200 OK\r\n\r\n", CauseTLS},
		{"http/1.0", strings.Replace(good(), "HTTP/1.1", "HTTP/1.0", 1), CauseTLS},
		{"no reason space", "HTTP/1.1 101\r\n\r\n", CauseTLS},
		{"letter code", "HTTP/1.1 1a1 X\r\n\r\n", CauseTLS},
		{"control in reason", "HTTP/1.1 101 Sw\x01\r\n\r\n", CauseTLS},
		{"wrong accept", strings.Replace(good(), acc, acceptValue("AAAAAAAAAAAAAAAAAAAAAA=="), 1), CauseTLS},
		{"accept repeated", good("Sec-WebSocket-Accept: " + acc + "\r\n"), CauseTLS},
		{"no upgrade", strings.Replace(good(), "Upgrade: websocket\r\n", "", 1), CauseTLS},
		{"upgrade other", strings.Replace(good(), "Upgrade: websocket", "Upgrade: h2c", 1), CauseTLS},
		{"upgrade repeated", good("Upgrade: websocket\r\n"), CauseTLS},
		{"no connection", strings.Replace(good(), "Connection: Upgrade\r\n", "", 1), CauseTLS},
		{"connection close", strings.Replace(good(), "Connection: Upgrade", "Connection: close", 1), CauseTLS},
		{"extensions", good("Sec-WebSocket-Extensions: permessage-deflate\r\n"), CauseTLS},
		{"empty extensions", good("Sec-WebSocket-Extensions:\r\n"), CauseTLS},
		{"obs-fold", good("X: a\r\n b\r\n"), CauseTLS},
		{"no colon", good("Bad header\r\n"), CauseTLS},
		{"space in name", good("Bad name: x\r\n"), CauseTLS},
		{"empty name", good(": x\r\n"), CauseTLS},
		{"control in value", good("X: a\x00b\r\n"), CauseTLS},
		{"del in value", good("X: a\x7fb\r\n"), CauseTLS},
		{"bare LF", good("X: a\nY: b\r\n"), CauseTLS},
		{"bare CR", good("X: a\rb\r\n"), CauseTLS},
	}
	for _, c := range cases {
		cause := c.cause
		err := checkUpgradeResponse([]byte(c.resp), rfcKey)
		switch {
		case cause == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case cause != "" && (err == nil || asError(t, err).Cause != cause || asError(t, err).Kind != Blocked):
			t.Errorf("%s: want %s, got %v", c.name, cause, err)
		}
	}
}

func TestReadUpgradeResponseKeepsRest(t *testing.T) {
	frame := []byte{0x82, 0x03, 'a', 'b', 'c'}
	r := iotest.OneByteReader(bytes.NewReader(append([]byte(good()), frame...)))
	rest, err := readUpgradeResponse(r, rfcKey)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := io.ReadAll(io.MultiReader(bytes.NewReader(rest), r))
	if !bytes.Equal(all, frame) {
		t.Fatalf("%x", all)
	}
	rest, err = readUpgradeResponse(bytes.NewReader(append([]byte(good()), frame...)), rfcKey)
	if err != nil || !bytes.Equal(rest, frame) {
		t.Fatal(rest, err)
	}
}

func TestReadUpgradeResponseLimits(t *testing.T) {
	long := good("X: " + strings.Repeat("a", maxUpgradeResponse) + "\r\n")
	_, err := readUpgradeResponse(strings.NewReader(long), rfcKey)
	if e := asError(t, err); e.Cause != CauseTLS || !errors.Is(err, errUpgradeTooLarge) {
		t.Fatal(err)
	}
	exact := good("X: ")
	exact = exact[:len(exact)-2] + strings.Repeat("a", maxUpgradeResponse-len(exact)-2) + "\r\n\r\n"
	if len(exact) != maxUpgradeResponse {
		t.Fatal(len(exact))
	}
	if _, err := readUpgradeResponse(strings.NewReader(exact), rfcKey); err != nil {
		t.Fatal(err)
	}
	_, err = readUpgradeResponse(strings.NewReader("HTTP/1.1 101 Switching"), rfcKey)
	if e := asError(t, err); e.Reason != "upgrade_io" || !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func FuzzUpgradeResponse(f *testing.F) {
	f.Add([]byte(good()))
	f.Add([]byte(good() + "\x82\x01x"))
	f.Add([]byte("HTTP/1.1 426 Upgrade Required\r\n\r\n"))
	f.Add([]byte(strings.Replace(good(), "Sec-WebSocket-Protocol: sw-tunnel.1\r\n", "", 1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		rest, err := readUpgradeResponse(bytes.NewReader(b), rfcKey)
		if err != nil {
			if KindOf(err) != Blocked {
				t.Fatal(err)
			}
			return
		}
		i := bytes.Index(b, []byte("\r\n\r\n"))
		if i < 0 || i+4 > maxUpgradeResponse {
			t.Fatal("accepted without a header block")
		}
		head := strings.ToLower(string(b[:i+4]))
		if !strings.HasPrefix(head, "http/1.1 101 ") || strings.Count(head, "\r\nsec-websocket-protocol:") != 1 ||
			strings.Count(head, strings.ToLower(acceptValue(rfcKey))) < 1 || strings.Contains(head, "\r\nsec-websocket-extensions:") {
			t.Fatalf("accepted %q", head)
		}
		if !bytes.HasPrefix(b[i+4:], rest) {
			t.Fatal("rest is not the bytes after the header block")
		}
	})
}
