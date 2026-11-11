package streams

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/visitor"
)

func TestNewNeedsGateTargetsDial(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestAcceptedForwardsOneRequest(t *testing.T) {
	e := newEnv(t, nil)
	e.mode.Store(visitor.Enforce)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	tok := token(appA, exp0)
	code, body, err := s.exchange(header(appA, tok), get("/a%2Fb?x=1;y", "X-Thing: 1\r\n"))
	if code != pb.ReplyCode_ACCEPTED || err != nil || body != okResponse {
		t.Fatalf("%v %q %v", code, body, err)
	}
	heads := tg.got()
	if len(heads) != 1 || !strings.HasPrefix(heads[0], "GET /a%2Fb?x=1;y HTTP/1.1\r\nHost: app.example.seawise.dev\r\n") {
		t.Fatalf("%q", heads)
	}
	if !strings.Contains(heads[0], "Connection: close\r\n") || !strings.Contains(heads[0], "X-Thing: 1\r\n") ||
		strings.Contains(strings.ToLower(heads[0]), "user-agent") {
		t.Fatalf("%q", heads[0])
	}
	l := e.waitLogged(1)
	en := l[0]
	if en.App != "loc-a" || en.Peer != "203.0.113.9" || en.Result != accesslog.ResultOK || en.Decision != visitor.CodeValid ||
		!strings.HasPrefix(en.Session, "sid:") || len(en.Session) != 16 || en.BytesOut != int64(len(okResponse)) || en.BytesIn == 0 ||
		en.Target != fmt.Sprintf("127.0.0.1:%d", tg.port) {
		t.Fatalf("%+v", en)
	}
	b, _ := json.Marshal(l)
	if strings.Contains(string(b), tok) || strings.Contains(string(b), strings.Split(tok, ".")[2]) || strings.Contains(e.logs.String(), strings.Split(tok, ".")[1]) {
		t.Fatal("token reached a log")
	}
	st := e.srv.Status()
	if st.Replies["ACCEPTED"] != 1 || st.Visitor.Counts[visitor.CodeValid] != 1 || st.Visitor.Mode != visitor.Enforce {
		t.Fatalf("%+v", st)
	}
}

func TestUnknownAppBeforeTheGate(t *testing.T) {
	e := newEnv(t, nil)
	e.mode.Store(visitor.Enforce)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	e.app(appB, "loc-b", tg.port, true)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	code, body, _ := s.exchange(header(appB, token(appB, exp0)), get("/"))
	if code != pb.ReplyCode_UNKNOWN_APP || body != "" {
		t.Fatalf("%v %q", code, body)
	}
	none := e.session(nil, 0)
	if code, _, _ := none.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_UNKNOWN_APP {
		t.Fatal("app id accepted before any RouteSet:", code)
	}
	if len(tg.got()) != 0 || len(e.logged()) != 0 || len(e.srv.Status().Visitor.Counts) != 0 {
		t.Fatal("gate, target or log reached for an unknown app")
	}
}

func TestAppOfAnotherSessionIsUnknown(t *testing.T) {
	e := newEnv(t, nil)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	e.app(appB, "loc-b", tg.port, false)
	one := e.session(routeSet(map[string]bool{appA: false}), 0)
	two := e.session(routeSet(map[string]bool{appB: false}), 0)
	if code, _, _ := two.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_UNKNOWN_APP {
		t.Fatal(code)
	}
	if code, _, _ := one.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_ACCEPTED {
		t.Fatal(code)
	}
	two.routes.Store(routeSet(map[string]bool{appA: false}))
	if code, _, _ := two.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_ACCEPTED {
		t.Fatal("updated routes not used:", code)
	}
}

func TestBadHeader(t *testing.T) {
	e := newEnv(t, nil)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	for name, frame := range map[string][]byte{
		"empty":       {0, 0},
		"too large":   {0x10, 0x01},
		"garbage":     {0, 3, 0xff, 0xff, 0xff},
		"bad version": mustFrame(t, func(h *pb.StreamHeader) { h.Version = 2 }),
		"raw tcp":     mustFrame(t, func(h *pb.StreamHeader) { h.Type = pb.StreamType_RAW_TCP }),
	} {
		t.Run(name, func(t *testing.T) {
			st, err := s.mux.OpenStream(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			_ = st.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := st.Write(append(frame, get("/")...)); err != nil {
				t.Fatal(err)
			}
			if code := readReply(t, st); code != pb.ReplyCode_BAD_HEADER {
				t.Fatal(code)
			}
			if b, err := io.ReadAll(st); err != nil || len(b) != 0 {
				t.Fatalf("bytes after a refusal: %q %v", b, err)
			}
		})
	}
}

// mustFrame encodes a valid header changed by f without validation.
func mustFrame(t *testing.T, f func(*pb.StreamHeader)) []byte {
	t.Helper()
	h := header(appA, "")
	f(h)
	b, err := marshalRaw(h)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
}

func TestRawTCPWithCapability(t *testing.T) {
	e := newEnv(t, nil)
	s := e.session(routeSet(map[string]bool{appA: false}), 0, "raw_tcp")
	st, err := s.mux.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = st.Write(mustFrame(t, func(h *pb.StreamHeader) { h.Type = pb.StreamType_RAW_TCP }))
	if code := readReply(t, st); code == pb.ReplyCode_BAD_HEADER {
		t.Fatal("negotiated capabilities not passed to the header parser")
	}
}

func TestHeaderTimeoutResets(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *forwarder.Config) { c.HeadTimeout = 150 * time.Millisecond })
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	for _, partial := range [][]byte{{0}, {0, 40, 8}} {
		st, err := s.mux.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = st.Write(partial)
		if _, err := io.ReadAll(st); !errors.Is(err, yamux.ErrStreamReset) {
			t.Fatalf("%v: %v", partial, err)
		}
		st.Close()
	}
}

func TestRequestHeadTimeoutResets(t *testing.T) {
	e := newEnv(t, func(c *Config, _ *forwarder.Config) { c.HeadTimeout = 150 * time.Millisecond })
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	st := s.open(header(appA, token(appA, exp0)), "GET / HTTP/1.1\r\n")
	defer st.Close()
	if code := readReply(t, st); code != pb.ReplyCode_ACCEPTED {
		t.Fatal(code)
	}
	if _, err := io.ReadAll(st); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal(err)
	}
	if l := e.waitLogged(1); l[0].Result != accesslog.ResultMalformed {
		t.Fatalf("%+v", l)
	}
}

func TestEnforceAndObserveWithoutToken(t *testing.T) {
	for _, mode := range []visitor.Mode{visitor.Enforce, visitor.Observe} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t, nil)
			e.mode.Store(mode)
			tg := okTarget(t)
			e.app(appA, "loc-a", tg.port, false)
			s := e.session(routeSet(map[string]bool{appA: false}), 0)
			code, body, _ := s.exchange(header(appA, ""), get("/"))
			l := e.waitLogged(1)
			if mode == visitor.Enforce {
				if code != pb.ReplyCode_TOKEN_REJECTED || body != "" || len(tg.got()) != 0 {
					t.Fatalf("%v %q %d", code, body, len(tg.got()))
				}
				if l[0].Result != accesslog.ResultDenied || l[0].Decision != visitor.CodeMissing || l[0].Session != "" || l[0].App != "loc-a" {
					t.Fatalf("%+v", l[0])
				}
				return
			}
			if code != pb.ReplyCode_ACCEPTED || body != okResponse {
				t.Fatalf("%v %q", code, body)
			}
			if l[0].Result != accesslog.ResultOK || l[0].Decision != visitor.CodeMissing {
				t.Fatalf("%+v", l[0])
			}
		})
	}
}

func TestPublicNeedsRouteAndServerState(t *testing.T) {
	for _, c := range []struct {
		route, server, stored bool
		want                  pb.ReplyCode
	}{
		{true, true, true, pb.ReplyCode_ACCEPTED},
		{true, false, true, pb.ReplyCode_TOKEN_REJECTED},
		{false, true, true, pb.ReplyCode_TOKEN_REJECTED},
		{false, false, true, pb.ReplyCode_TOKEN_REJECTED},
		{true, true, false, pb.ReplyCode_TOKEN_REJECTED},
	} {
		t.Run(fmt.Sprintf("route=%v server=%v stored=%v", c.route, c.server, c.stored), func(t *testing.T) {
			e := newEnv(t, nil)
			e.mode.Store(visitor.Enforce)
			tg := okTarget(t)
			if c.stored {
				e.app(appA, "loc-a", tg.port, c.server)
			}
			s := e.session(routeSet(map[string]bool{appA: c.route}), 0)
			if code, _, _ := s.exchange(header(appA, ""), get("/")); code != c.want {
				t.Fatal(code)
			}
		})
	}
}

func TestTwoTargetsForOneAppArePrivateAndUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, true)
	e.app(appA, "loc-a2", tg.port, true)
	s := e.session(routeSet(map[string]bool{appA: true}), 0)
	e.mode.Store(visitor.Enforce)
	if code, _, _ := s.exchange(header(appA, ""), get("/")); code != pb.ReplyCode_TOKEN_REJECTED {
		t.Fatal(code)
	}
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal(code)
	}
}

func TestSeaWiseHeadersStrippedInBothModes(t *testing.T) {
	for _, mode := range []visitor.Mode{visitor.Observe, visitor.Enforce} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t, nil)
			e.mode.Store(mode)
			tg := okTarget(t)
			e.app(appA, "loc-a", tg.port, false)
			s := e.session(routeSet(map[string]bool{appA: false}), 0)
			req := get("/", "SeaWise-Visitor-Token: smuggled1\r\n", "seawise-stale-ok: smuggled2\r\n", "SEAWISE-VISITOR-TOKEN: smuggled3\r\n",
				"Seawise_Visitor_Token: smuggled4\r\n", "sEaWiSe_StAlE_oK: smuggled5\r\n", "X-Keep: yes\r\n")
			code, _, _ := s.exchange(header(appA, token(appA, exp0)), req)
			if code != pb.ReplyCode_ACCEPTED {
				t.Fatal(code)
			}
			h := tg.got()
			if len(h) != 1 || strings.Contains(h[0], "smuggled") || strings.Contains(strings.ToLower(h[0]), "seawise-") ||
				strings.Contains(strings.ToLower(h[0]), "seawise_") || !strings.Contains(h[0], "X-Keep: yes") {
				t.Fatalf("%q", h)
			}
		})
	}
}

func TestEdgeTimeNeverUsed(t *testing.T) {
	e := newEnv(t, nil)
	e.mode.Store(visitor.Enforce)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	e.now.Store(exp0 + visitor.Leeway + 1)
	h := header(appA, token(appA, exp0))
	h.EdgeTimeMs = (exp0 - 100) * 1000
	if code, _, _ := s.exchange(h, get("/")); code != pb.ReplyCode_TOKEN_REJECTED {
		t.Fatal("edge time used for freshness:", code)
	}
	e.now.Store(exp0 + visitor.Leeway)
	h.EdgeTimeMs = (exp0 + 100000) * 1000
	if code, _, _ := s.exchange(h, get("/")); code != pb.ReplyCode_ACCEPTED {
		t.Fatal(code)
	}
}

func TestStaleOkEndToEnd(t *testing.T) {
	e := newEnv(t, nil)
	e.mode.Store(visitor.Enforce)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	e.now.Store(exp0 + 1000)
	h := header(appA, token(appA, exp0))
	if code, _, _ := s.exchange(h, get("/")); code != pb.ReplyCode_TOKEN_REJECTED {
		t.Fatal(code)
	}
	h.StaleOkUntil = staleOk(testKey("edge"), appA, exp0)
	if code, body, _ := s.exchange(h, get("/")); code != pb.ReplyCode_ACCEPTED || body != okResponse {
		t.Fatal(code, body)
	}
	e.waitLogged(2)
	h.StaleOkUntil = staleOk(testKey("visitor"), appA, exp0)
	if code, _, _ := s.exchange(h, get("/")); code != pb.ReplyCode_TOKEN_REJECTED {
		t.Fatal("stale-ok by a visitor key accepted:", code)
	}
	l := e.waitLogged(3)
	if l[0].Decision != visitor.CodeExpired || l[1].Decision != visitor.CodeStaleOk || !strings.HasPrefix(l[2].Decision, "stale_") || l[2].Result != accesslog.ResultDenied {
		t.Fatalf("%+v", l)
	}
}

func TestWrongAudience(t *testing.T) {
	e := newEnv(t, nil)
	e.mode.Store(visitor.Enforce)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	e.app(appB, "loc-b", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false, appB: false}), 0)
	if code, _, _ := s.exchange(header(appA, token(appB, exp0)), get("/")); code != pb.ReplyCode_TOKEN_REJECTED {
		t.Fatal(code)
	}
}

func TestTargetUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	tg := okTarget(t)
	e.app(appA, "loc-a", closedPort(t), false)
	s := e.session(routeSet(map[string]bool{appA: false, appB: false, "6d1f3c2a-8b4e-4f7a-9c0d-0000000000ff": false}), 0)
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal("unreachable:", code)
	}
	if code, _, _ := s.exchange(header(appB, token(appB, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal("no stored target:", code)
	}
	ts := *e.targets.Load()
	ts[0].Host, ts[0].Port = "169.254.169.254", 80
	e.targets.Store(&ts)
	e.sync()
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal("refused by policy:", code)
	}
	e.fwd.Sync(nil)
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal("not served:", code)
	}
	ts[0].Disabled = true
	e.targets.Store(&ts)
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal("disabled:", code)
	}
	l := e.waitLogged(3)
	if l[0].Result != accesslog.ResultUnreachable || l[1].Result != accesslog.ResultRefused || l[2].Result != accesslog.ResultRefused {
		t.Fatalf("%+v", l)
	}
	_ = tg
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func TestThisMachineTarget(t *testing.T) {
	e := newEnv(t, nil)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	ts := *e.targets.Load()
	ts[0].Host = "0.0.0.0"
	e.targets.Store(&ts)
	e.sync()
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	if code, body, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_ACCEPTED || body != okResponse {
		t.Fatal(code, body)
	}
}

func TestBodies(t *testing.T) {
	echo := newTarget(t, func(c net.Conn, br *bufio.Reader, head string) {
		var body []byte
		if strings.Contains(head, "Transfer-Encoding: chunked") {
			for !bytes.HasSuffix(body, []byte("0\r\n\r\n")) {
				b, err := br.ReadByte()
				if err != nil {
					break
				}
				body = append(body, b)
			}
		} else if i := strings.Index(head, "Content-Length: "); i >= 0 {
			var n int
			fmt.Sscanf(head[i+len("Content-Length: "):], "%d", &n)
			body = make([]byte, n)
			_, _ = io.ReadFull(br, body)
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	})
	e := newEnv(t, nil)
	e.app(appA, "loc-a", echo.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	tok := token(appA, exp0)
	_, body, _ := s.exchange(header(appA, tok), "POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")
	if !strings.HasSuffix(body, "\r\n\r\nhello") {
		t.Fatalf("%q", body)
	}
	_, body, _ = s.exchange(header(appA, tok), "POST /up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
	if !strings.Contains(body, "abc") || !strings.Contains(body, "de") || !strings.HasSuffix(body, "0\r\n\r\n") {
		t.Fatalf("%q", body)
	}
	heads := echo.got()
	if strings.Contains(heads[1], "Content-Length") || !strings.Contains(heads[1], "Transfer-Encoding: chunked") {
		t.Fatalf("%q", heads[1])
	}
}

func TestBothFramingsRefused(t *testing.T) {
	e := newEnv(t, nil)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	code, _, err := s.exchange(header(appA, token(appA, exp0)), "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	if code == pb.ReplyCode_BAD_HEADER || !errors.Is(err, yamux.ErrStreamReset) || strings.Contains(strings.Join(tg.got(), ""), "POST") {
		t.Fatal(code, err, tg.got())
	}
}

func TestTrailingBytesReset(t *testing.T) {
	e := newEnv(t, nil)
	slow := newTarget(t, func(c net.Conn, _ *bufio.Reader, _ string) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(c, okResponse)
	})
	e.app(appA, "loc-a", slow.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	_, _, err := s.exchange(header(appA, token(appA, exp0)), get("/")+get("/second"))
	if !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal("second request on one stream not reset:", err)
	}
	st := s.open(header(appA, token(appA, exp0)), get("/"))
	readReply(t, st)
	time.Sleep(20 * time.Millisecond)
	_, _ = st.Write([]byte("X"))
	if _, err := io.ReadAll(st); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal("late byte not reset:", err)
	}
	st.Close()
	if l := e.waitLogged(2); l[0].Result != accesslog.ResultMalformed || l[1].Result != accesslog.ResultMalformed {
		t.Fatalf("%+v", l)
	}
}

func TestInterimThenFinalPassedExactly(t *testing.T) {
	resp := "HTTP/1.1 103 Early Hints\r\nlink: </a>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nx-ODD-case:  v \r\nContent-Length: 2\r\n\r\nok"
	tg := newTarget(t, func(c net.Conn, _ *bufio.Reader, _ string) { _, _ = io.WriteString(c, resp) })
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	if code, body, err := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_ACCEPTED || body != resp || err != nil {
		t.Fatalf("%v %q %v", code, body, err)
	}
}

func TestBadResponseHeadResets(t *testing.T) {
	for name, resp := range map[string]string{
		"not http":     "SSH-2.0-OpenSSH\r\n\r\n",
		"too large":    "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", MaxResponseHead) + "\r\n\r\n",
		"101 unasked":  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nraw",
		"closed early": "HTTP/1.1 200 OK\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			tg := newTarget(t, func(c net.Conn, _ *bufio.Reader, _ string) { _, _ = io.WriteString(c, resp) })
			e := newEnv(t, nil)
			e.app(appA, "loc-a", tg.port, false)
			s := e.session(routeSet(map[string]bool{appA: false}), 0)
			if _, _, err := s.exchange(header(appA, token(appA, exp0)), get("/")); !errors.Is(err, yamux.ErrStreamReset) {
				t.Fatal(err)
			}
		})
	}
}

func upgradeTarget(t *testing.T, delay time.Duration, status string) *rawTarget {
	return newTarget(t, func(c net.Conn, br *bufio.Reader, _ string) {
		time.Sleep(delay)
		_, _ = io.WriteString(c, status)
		_, _ = io.Copy(c, br)
	})
}

const upgradeReq = "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

func TestUpgradeCarriesRawBytesAfter101(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	tg := upgradeTarget(t, 0, sw)
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	st := s.open(header(appA, token(appA, exp0)), upgradeReq)
	defer st.Close()
	if code := readReply(t, st); code != pb.ReplyCode_ACCEPTED {
		t.Fatal(code)
	}
	head := make([]byte, len(sw))
	if _, err := io.ReadFull(st, head); err != nil || string(head) != sw {
		t.Fatalf("%q %v", head, err)
	}
	for _, msg := range []string{"ping", "pong-pong"} {
		if _, err := st.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(st, got); err != nil || string(got) != msg {
			t.Fatalf("%q %v", got, err)
		}
	}
	if h := tg.got(); len(h) != 1 || strings.Contains(h[0], "close") || !strings.Contains(h[0], "Upgrade: websocket") {
		t.Fatalf("%q", h)
	}
	_ = st.CloseWrite()
	if b, err := io.ReadAll(st); err != nil || len(b) != 0 {
		t.Fatalf("%q %v", b, err)
	}
	if l := e.waitLogged(1); l[0].Result != accesslog.ResultOK || l[0].BytesOut != int64(len(sw)+13) {
		t.Fatalf("%+v", l)
	}
}

func TestBytesBefore101Reset(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	got := make(chan string, 1)
	tg := newTarget(t, func(c net.Conn, br *bufio.Reader, _ string) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(c, sw)
		b, _ := io.ReadAll(br)
		got <- string(b)
	})
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	_, _, err := s.exchange(header(appA, token(appA, exp0)), upgradeReq+"early")
	if !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if b != "" {
			t.Fatalf("early bytes reached the app: %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target not closed")
	}
}

func TestBytesAfterRefusedUpgradeReset(t *testing.T) {
	tg := upgradeTarget(t, 0, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	st := s.open(header(appA, token(appA, exp0)), upgradeReq)
	defer st.Close()
	readReply(t, st)
	r := bufio.NewReader(st)
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 400") {
		t.Fatal(line, err)
	}
	_, _ = st.Write([]byte("raw"))
	if _, err := io.ReadAll(r); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal(err)
	}
}

func TestStreamCapBusy(t *testing.T) {
	hold := make(chan struct{})
	tg := newTarget(t, func(c net.Conn, _ *bufio.Reader, _ string) {
		<-hold
		_, _ = io.WriteString(c, okResponse)
	})
	defer close(hold)
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 1)
	first := s.open(header(appA, token(appA, exp0)), get("/"))
	defer first.Close()
	readReply(t, first)
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_AGENT_BUSY {
		t.Fatal(code)
	}
	if e.srv.Status().Active != 1 {
		t.Fatal(e.srv.Status())
	}
}

func TestAppCapBusy(t *testing.T) {
	hold := make(chan struct{})
	tg := newTarget(t, func(c net.Conn, _ *bufio.Reader, _ string) {
		<-hold
		_, _ = io.WriteString(c, okResponse)
	})
	defer close(hold)
	e := newEnv(t, func(_ *Config, f *forwarder.Config) { f.MaxConns = 1 })
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	first := s.open(header(appA, token(appA, exp0)), get("/"))
	defer first.Close()
	readReply(t, first)
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_AGENT_BUSY {
		t.Fatal(code)
	}
	if l := e.waitLogged(1); l[0].Result != accesslog.ResultBusy {
		t.Fatalf("%+v", l)
	}
}

func TestIdleTimeout(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	tg := upgradeTarget(t, 0, sw)
	e := newEnv(t, func(c *Config, _ *forwarder.Config) { c.IdleTimeout = 200 * time.Millisecond })
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	st := s.open(header(appA, token(appA, exp0)), upgradeReq)
	defer st.Close()
	readReply(t, st)
	start := time.Now()
	if _, err := io.ReadAll(st); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 3*time.Second {
		t.Fatal(d)
	}
}

func TestKillSwitchClosesUpstreams(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	tg := upgradeTarget(t, 0, sw)
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	st := s.open(header(appA, token(appA, exp0)), upgradeReq)
	defer st.Close()
	readReply(t, st)
	head := make([]byte, len(sw))
	if _, err := io.ReadFull(st, head); err != nil {
		t.Fatal(err)
	}
	e.fwd.Sync(nil)
	if _, err := io.ReadAll(st); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal("upgraded stream survived the kill switch:", err)
	}
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TARGET_UNAVAILABLE {
		t.Fatal(code)
	}
}

func TestSessionEndResetsStreamsAndLeaksNothing(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	tg := upgradeTarget(t, 0, sw)
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	base := numGoroutine()
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	var open []*yamux.Stream
	for range 5 {
		st := s.open(header(appA, token(appA, exp0)), upgradeReq)
		readReply(t, st)
		open = append(open, st)
	}
	stalled, err := s.mux.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	for _, st := range append(open, stalled) {
		_ = st.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(st); err == nil {
			t.Fatal("stream survived the session")
		}
	}
	_ = s.mux.Close()
	if e.srv.Status().Active != 0 {
		t.Fatal(e.srv.Status())
	}
	e.waitLogged(5)
	goroutines(t, base+tgGoroutines(tg))
}

func TestMuxCloseEndsServe(t *testing.T) {
	e := newEnv(t, nil)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	_ = s.agent.Close()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestManyStreamsNoLeak(t *testing.T) {
	tg := okTarget(t)
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	base := numGoroutine()
	errs := make(chan error, 64)
	for range 64 {
		go func() {
			code, body, err := s.exchange(header(appA, token(appA, exp0)), get("/"))
			if code != pb.ReplyCode_ACCEPTED || body != okResponse || err != nil {
				err = fmt.Errorf("%v %q %v", code, body, err)
			}
			errs <- err
		}()
	}
	for range 64 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	goroutines(t, base+2)
	idle(t, e.srv)
}

func idle(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.Status().Active != 0 {
		if time.Now().After(deadline) {
			t.Fatal(s.Status())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The app sees no half-close before it answers: some servers drop a
// request whose connection is half-closed.
func TestNoHalfCloseBeforeResponse(t *testing.T) {
	early := make(chan bool, 1)
	tg := newTarget(t, func(c net.Conn, br *bufio.Reader, _ string) {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := br.ReadByte()
		early <- errors.Is(err, io.EOF)
		_, _ = io.WriteString(c, okResponse)
	})
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	if code, body, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_ACCEPTED || body != okResponse {
		t.Fatal(code, body)
	}
	if <-early {
		t.Fatal("upstream half-closed before the response")
	}
}

// Only WebSocket upgrades are carried; any other upgrade (h2c here) goes
// to the app as a plain request and a 101 to it resets the stream.
func TestOnlyWebSocketUpgrades(t *testing.T) {
	h2c := "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
	for name, c := range map[string]struct{ req, resp string }{
		"h2c":           {h2c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\nPRI"},
		"two protocols": {"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket, h2c\r\nConnection: Upgrade\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"},
		"with a body":   {"POST / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 2\r\n\r\nab", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"},
		"chunked":       {"POST / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"},
		"zero length":   {"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tg := newTarget(t, func(conn net.Conn, br *bufio.Reader, _ string) {
				_, _ = io.WriteString(conn, c.resp)
				_, _ = io.Copy(io.Discard, br)
			})
			e := newEnv(t, nil)
			e.app(appA, "loc-a", tg.port, false)
			s := e.session(routeSet(map[string]bool{appA: false}), 0)
			_, _, err := s.exchange(header(appA, token(appA, exp0)), c.req)
			if !errors.Is(err, yamux.ErrStreamReset) {
				t.Fatal("a 101 to a non-WebSocket request was carried:", err)
			}
			h := tg.got()
			if len(h) != 1 || strings.Contains(strings.ToLower(h[0]), "upgrade: ") || !strings.Contains(h[0], "Connection: close\r\n") {
				t.Fatalf("%q", h)
			}
		})
	}
}

func TestWebSocket101MustNameWebSocket(t *testing.T) {
	for name, resp := range map[string]string{
		"no upgrade header": "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\nraw",
		"other protocol":    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\nraw",
	} {
		t.Run(name, func(t *testing.T) {
			tg := upgradeTarget(t, 0, resp)
			e := newEnv(t, nil)
			e.app(appA, "loc-a", tg.port, false)
			s := e.session(routeSet(map[string]bool{appA: false}), 0)
			if _, _, err := s.exchange(header(appA, token(appA, exp0)), upgradeReq); !errors.Is(err, yamux.ErrStreamReset) {
				t.Fatal(err)
			}
		})
	}
	tg := upgradeTarget(t, 0, "HTTP/1.1 101 Switching Protocols\r\nupgrade:  WebSocket \r\nConnection: Upgrade\r\n\r\n")
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	st := s.open(header(appA, token(appA, exp0)), strings.Replace(upgradeReq, "websocket", "WebSocket", 1))
	defer st.Close()
	if code := readReply(t, st); code != pb.ReplyCode_ACCEPTED {
		t.Fatal(code)
	}
	r := bufio.NewReader(st)
	if _, err := http.ReadResponse(r, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = st.Write([]byte("hi"))
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil || string(b) != "hi" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestAppEndResetsOnlyThatAppsStreams(t *testing.T) {
	sw := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	tg := upgradeTarget(t, 0, sw)
	e := newEnv(t, nil)
	e.app(appA, "loc-a", tg.port, false)
	e.app(appB, "loc-b", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false, appB: false}), 0)
	open := func(app string) *yamux.Stream {
		st := s.open(header(app, token(app, exp0)), upgradeReq)
		if code := readReply(t, st); code != pb.ReplyCode_ACCEPTED {
			t.Fatal(code)
		}
		head := make([]byte, len(sw))
		if _, err := io.ReadFull(st, head); err != nil {
			t.Fatal(err)
		}
		return st
	}
	a, b := open(appA), open(appB)
	defer a.Close()
	defer b.Close()
	s.ended.Push(appA)
	if _, err := io.ReadAll(a); !errors.Is(err, yamux.ErrStreamReset) {
		t.Fatal("revoked app's stream survived:", err)
	}
	_, _ = b.Write([]byte("ok"))
	got := make([]byte, 2)
	if _, err := io.ReadFull(b, got); err != nil || string(got) != "ok" {
		t.Fatal("other app's stream ended:", err)
	}
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_UNKNOWN_APP {
		t.Fatal("revoked app accepted on the same RouteSet:", code)
	}
	rs := routeSet(map[string]bool{appA: false, appB: false})
	rs.Version = 2
	s.routes.Store(rs)
	again := open(appA)
	_ = again.Close()
}

func TestNoSignedTimeYet(t *testing.T) {
	for _, mode := range []visitor.Mode{visitor.Enforce, visitor.Observe} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t, func(c *Config, _ *forwarder.Config) { c.ClockReady = func() bool { return false } })
			e.mode.Store(mode)
			tg := okTarget(t)
			e.app(appA, "loc-a", tg.port, false)
			e.app(appB, "loc-b", tg.port, true)
			s := e.session(routeSet(map[string]bool{appA: false, appB: true}), 0)
			code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/"))
			if mode == visitor.Enforce && code != pb.ReplyCode_TOKEN_REJECTED || mode == visitor.Observe && code != pb.ReplyCode_ACCEPTED {
				t.Fatal(code)
			}
			l := e.waitLogged(1)
			if mode == visitor.Enforce && (l[0].Decision != CodeNoSignedTime || l[0].Result != accesslog.ResultDenied || l[0].Session != "") {
				t.Fatalf("%+v", l[0])
			}
			if code, _, _ := s.exchange(header(appB, ""), get("/")); code != pb.ReplyCode_ACCEPTED {
				t.Fatal("public app refused without signed time:", code)
			}
			if e.srv.Status().NoSignedTime != 1 {
				t.Fatal(e.srv.Status())
			}
		})
	}
}

func TestEnforceRecoversOnceSignedTimeArrives(t *testing.T) {
	var ready atomic.Bool
	e := newEnv(t, func(c *Config, _ *forwarder.Config) { c.ClockReady = ready.Load })
	e.mode.Store(visitor.Enforce)
	tg := okTarget(t)
	e.app(appA, "loc-a", tg.port, false)
	s := e.session(routeSet(map[string]bool{appA: false}), 0)
	if code, _, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_TOKEN_REJECTED {
		t.Fatal(code)
	}
	ready.Store(true)
	if code, body, _ := s.exchange(header(appA, token(appA, exp0)), get("/")); code != pb.ReplyCode_ACCEPTED || body != okResponse {
		t.Fatal(code, body)
	}
}
