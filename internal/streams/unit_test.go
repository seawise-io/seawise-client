package streams

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/httpwire"

	"github.com/seawise/client/internal/accesslog"
)

func TestStatusOf(t *testing.T) {
	good := map[string]int{
		"HTTP/1.1 200 OK\r\n": 200, "HTTP/1.0 101\r\n": 101, "HTTP/1.1 100 \r\n": 100, "HTTP/1.1 999\n": 999, "HTTP/1.9 404 x": 404,
	}
	for h, want := range good {
		if got, ok := statusOf([]byte(h)); !ok || got != want {
			t.Errorf("%q: %d %v", h, got, ok)
		}
	}
	for _, h := range []string{"HTTP/1.1 200", "HTTP/1.1 099 x\r\n", "HTTP/1.1 20x x\r\n", "HTTP/1.a 200 x\r\n", "HTTP/1./ 200 x\r\n",
		"HTTP/1.: 200 x\r\n", "HTTP/1.1  200 x\r\n", "HTTP/1.12000 x\r\n", "HTTP/2.0 200 x\r\n", "HTTP/1.1 2000\r\n", "HTTP/1.1 200x\r\n",
		"HTTP/1.1 -20 x\r\n", "HTTP/1.1 1e2 x\r\n"} {
		if got, ok := statusOf([]byte(h)); ok {
			t.Errorf("%q accepted as %d", h, got)
		}
	}
}

func TestReadHeadBounds(t *testing.T) {
	line := "HTTP/1.1 200 OK\r\n"
	pad := MaxResponseHead - len(line) - len("X: \r\n") - 2
	exact := line + "X: " + strings.Repeat("a", pad) + "\r\n\r\n"
	if len(exact) != MaxResponseHead {
		t.Fatal(len(exact))
	}
	head, st, err := readHead(bufio.NewReaderSize(strings.NewReader(exact+"body"), 16))
	if err != nil || st != 200 || string(head) != exact {
		t.Fatal(st, err)
	}
	over := line + "X: " + strings.Repeat("a", pad+1) + "\r\n\r\n"
	if _, _, err := readHead(bufio.NewReaderSize(strings.NewReader(over), 16)); !errors.Is(err, errHead) {
		t.Fatal(err)
	}
	for _, h := range []string{"\r\nHTTP/1.1 200 OK\r\n\r\n", "\nHTTP/1.1 200 OK\r\n\r\n"} {
		if _, _, err := readHead(bufio.NewReader(strings.NewReader(h))); err == nil {
			t.Errorf("%q: an empty first line ended the head", h)
		}
	}
	head, _, err = readHead(bufio.NewReader(strings.NewReader("HTTP/1.1 204 x\nA: b\n\nrest")))
	if err != nil || string(head) != "HTTP/1.1 204 x\nA: b\n\n" {
		t.Fatalf("%q %v", head, err)
	}
	if _, _, err := readHead(bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nA: b\r\n"))); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func readReq(t *testing.T, s string) *http.Request {
	t.Helper()
	r, err := httpwire.ReadRequest(bufio.NewReader(strings.NewReader(s)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWriteRequest(t *testing.T) {
	var b bytes.Buffer
	r := readReq(t, "POST /p?q HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nx")
	if err := writeRequest(&b, r, false); err != nil {
		t.Fatal(err)
	}
	if b.String() != "POST /p?q HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx" {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	r = readReq(t, "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	if err := writeRequest(&b, r, true); err != nil {
		t.Fatal(err)
	}
	if b.String() != "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" {
		t.Fatalf("%q", b.String())
	}
	b.Reset()
	r = readReq(t, "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTrailer: T\r\n\r\n2\r\nab\r\n0\r\nT: v\r\n\r\n")
	if err := writeRequest(&b, r, false); err != nil {
		t.Fatal(err)
	}
	if b.String() != "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n0\r\nT: v\r\n\r\n" {
		t.Fatalf("%q", b.String())
	}
	r = readReq(t, "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nab")
	if err := writeRequest(io.Discard, r, false); httpwire.CodeOf(err) != httpwire.CodeTruncated {
		t.Fatal(err)
	}
}

func runMem(t *testing.T, req, resp string) (*exchange, *memStream, *memUp, string) {
	t.Helper()
	s := fuzzServer(t)
	st := &memStream{in: bytes.NewReader([]byte(req))}
	up := &memUp{resp: bytes.NewReader([]byte(resp))}
	x := newExchange(s, st, up)
	return x, st, up, x.run()
}

func TestExchangeResults(t *testing.T) {
	x, st, up, res := runMem(t, get("/"), okResponse)
	if res != accesslog.ResultOK || string(st.written()) != okResponse || x.out.Load() != int64(len(okResponse)) ||
		x.in.Load() != int64(up.got.Len()) || x.aborted.Load() {
		t.Fatal(res, x.aborted.Load())
	}
	for name, c := range map[string]struct{ req, want string }{
		"trailing":     {get("/") + "X", accesslog.ResultMalformed},
		"bad head":     {"GET / HTTP/1.0\r\nHost: h\r\n\r\n", accesslog.ResultMalformed},
		"short body":   {"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nab", accesslog.ResultMalformed},
		"bad chunk":    {"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", accesslog.ResultMalformed},
		"upgrade eof":  {upgradeReq, accesslog.ResultOK},
		"pre-101 byte": {upgradeReq + "x", accesslog.ResultMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			resp := okResponse
			if strings.HasPrefix(c.req, "GET /ws") {
				resp = "HTTP/1.1 400 x\r\nContent-Length: 0\r\n\r\n"
			}
			x, _, _, res := runMem(t, c.req, resp)
			if res != c.want {
				t.Fatal(res)
			}
			if c.want == accesslog.ResultMalformed && !x.aborted.Load() {
				t.Fatal("not aborted")
			}
		})
	}
}

func TestExchangeUpgradeRaw(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	s := fuzzServer(t)
	pr, pw := io.Pipe()
	st := &pipeStream{r: pr}
	up := &memUp{resp: bytes.NewReader([]byte(sw + "down"))}
	x := newExchange(s, st, up)
	done := make(chan string)
	go func() { done <- x.run() }()
	_, _ = io.WriteString(pw, upgradeReq)
	deadline := time.Now().Add(5 * time.Second)
	for !x.upgraded.Load() {
		if time.Now().After(deadline) {
			t.Fatal("no upgrade")
		}
		time.Sleep(time.Millisecond)
	}
	_, _ = io.WriteString(pw, "up")
	_ = pw.Close()
	if res := <-done; res != accesslog.ResultOK {
		t.Fatal(res)
	}
	if !strings.HasSuffix(up.got.String(), "\r\n\r\nup") || st.out.String() != sw+"down" {
		t.Fatalf("%q %q", up.got.String(), st.out.String())
	}
}

type pipeStream struct {
	memStream
	r io.Reader
}

func (p *pipeStream) Read(b []byte) (int, error) { return p.r.Read(b) }

func TestMeterTouchesOnlyOnBytes(t *testing.T) {
	x := newExchange(nil, nil, nil)
	x.last.Store(1)
	_, _ = meterReader{r: strings.NewReader(""), x: x}.Read(make([]byte, 4))
	n := &x.in
	_, _ = meterWriter{w: io.Discard, n: n, x: x}.Write(nil)
	if x.last.Load() != 1 {
		t.Fatal("touched without bytes")
	}
	_, _ = meterReader{r: strings.NewReader("a"), x: x}.Read(make([]byte, 4))
	if x.last.Load() == 1 {
		t.Fatal("not touched")
	}
	x.last.Store(1)
	_, _ = meterWriter{w: io.Discard, n: n, x: x}.Write([]byte("ab"))
	if x.last.Load() == 1 || n.Load() != 2 {
		t.Fatal("writer")
	}
}

func TestWatchKeepsActiveExchange(t *testing.T) {
	s := fuzzServer(t)
	s.cfg.IdleTimeout = 80 * time.Millisecond
	x := newExchange(s, &memStream{in: bytes.NewReader(nil)}, &memUp{resp: bytes.NewReader(nil)})
	x.touch()
	done := make(chan struct{})
	go x.watch(done)
	for range 10 {
		time.Sleep(20 * time.Millisecond)
		x.touch()
	}
	if x.aborted.Load() {
		t.Fatal("active exchange aborted")
	}
	start := time.Now()
	for !x.aborted.Load() {
		if time.Since(start) > 2*time.Second {
			t.Fatal("idle exchange not aborted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if d := time.Since(start); d < 60*time.Millisecond {
		t.Fatal("aborted early", d)
	}
	close(done)
}

func TestDefaults(t *testing.T) {
	s := fuzzServer(t)
	s2, err := New(Config{Gate: s.cfg.Gate, Targets: s.cfg.Targets, Dial: s.cfg.Dial})
	if err != nil {
		t.Fatal(err)
	}
	c := s2.cfg
	if c.MaxStreams != 128 || c.HeadTimeout != 10*time.Second || c.IdleTimeout != time.Hour || c.CloseWait != DefaultCloseWait || c.Now == nil {
		t.Fatalf("%+v", c)
	}
}

// Idle time is measured from the exchange's monotonic start, so a wall
// clock step cannot cut or extend a stream.
func TestIdleUsesMonotonicOffset(t *testing.T) {
	x := newExchange(fuzzServer(t), &memStream{in: bytes.NewReader(nil)}, &memUp{resp: bytes.NewReader(nil)})
	time.Sleep(5 * time.Millisecond)
	x.touch()
	if d := time.Duration(x.last.Load()); d < 5*time.Millisecond || d > time.Minute {
		t.Fatalf("last is not an offset from the start: %d", x.last.Load())
	}
	if x.idleFor() > time.Minute {
		t.Fatal(x.idleFor())
	}
}

func TestUpgradesTo(t *testing.T) {
	for h, want := range map[string]bool{
		"HTTP/1.1 101 x\r\nUpgrade: websocket\r\n\r\n":                       true,
		"HTTP/1.1 101 x\r\nupgrade:\tWebSocket \r\n\r\n":                     true,
		"HTTP/1.1 101 x\nUpgrade: websocket\n\n":                             true,
		"HTTP/1.1 101 x\r\n\r\n":                                             false,
		"HTTP/1.1 101 x\r\nUpgrade: h2c\r\n\r\n":                             false,
		"HTTP/1.1 101 x\r\nUpgrade: websocket\r\nUpgrade: websocket\r\n\r\n": false,
		"HTTP/1.1 101 x\r\nUpgrade: websocket, h2c\r\n\r\n":                  false,
		"HTTP/1.1 101 x\r\nX-Upgrade: websocket\r\n\r\n":                     false,
		"HTTP/1.1 101 Upgrade: websocket\r\n\r\n":                            false,
	} {
		if upgradesTo([]byte(h), "websocket") != want {
			t.Errorf("%q: want %v", h, want)
		}
	}
}

func TestRegistry(t *testing.T) {
	r := newRegistry()
	var ended []string
	cancel := func(app string) context.CancelFunc { return func() { ended = append(ended, app) } }
	a := r.add("a", 1, cancel("a"))
	b := r.add("b", 1, cancel("b"))
	r.end([]string{"a"}, 1)
	if len(ended) != 1 || ended[0] != "a" || r.add("a", 1, cancel("a")) != nil {
		t.Fatal(ended)
	}
	r.remove("a", a)
	r.remove("b", b)
	if len(r.active) != 0 {
		t.Fatal("ended streams kept:", r.active)
	}
	if r.add("a", 2, cancel("a")) == nil {
		t.Fatal("app refused after a new RouteSet version")
	}
}

func TestRegistryEndAtNewerVersion(t *testing.T) {
	r := newRegistry()
	r.end([]string{"a"}, 3)
	for _, v := range []int64{1, 2, 3} {
		if r.add("a", v, func() {}) != nil {
			t.Fatalf("stream added at version %d after an end at 3", v)
		}
	}
	if r.add("a", 4, func() {}) == nil {
		t.Fatal("refused at a newer version")
	}
}
