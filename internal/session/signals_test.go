package session

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

func TestRouteSetSignedTime(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	nonce := claims.TimeNonce(c.info.TimeNonce)
	good := sign(t, "control", protocol.TypTime, map[string]any{"server_id": testServer, "time": 1700000500, "nonce": nonce})
	m := routeSetMsg(t, 1, testSessionID)
	m.GetRouteSet().SignedTime = good
	c.in <- m
	h.wait("signed time", func(s Status) bool { return s.Up && s.SignedTime == 1700000500 })
	bad := sign(t, "control", protocol.TypTime, map[string]any{"server_id": testServer, "time": 1800000000, "nonce": "BBBBBBBBBBBBBBBBBBBBBB"})
	m = routeSetMsg(t, 2, testSessionID)
	m.GetRouteSet().SignedTime = bad
	c.in <- m
	c.expect(t, "RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 2 })
	if s := h.m.Status(); s.SignedTime != 1700000500 || !s.Up {
		t.Fatalf("unbound signed time applied: %+v", s)
	}
}

func TestPingNoncesIncrease(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.setRx(h.clock.Now())
	h.advance(20 * time.Second)
	p1 := c.expect(t, "Ping", isPing).GetPing().GetNonce()
	c.setRx(h.clock.Now())
	h.advance(20 * time.Second)
	p2 := c.expect(t, "Ping", isPing).GetPing().GetNonce()
	if p1 != 1 || p2 != 2 {
		t.Fatal(p1, p2)
	}
}

func TestHTTPSHeartbeatReportsSessionState(t *testing.T) {
	h := newHarness(t)
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	<-h.hb.nonces
	h.hb.mu.Lock()
	connected := append([]bool(nil), h.hb.connected...)
	h.hb.mu.Unlock()
	if len(connected) == 0 || connected[0] {
		t.Fatalf("frp_connected without a session: %v", connected)
	}
}

func TestStreamZeroNonceRefusedTwiceFallsBack(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_KILL_SWITCH, Action: pb.DrainAction_HOLD, DeadlineMs: 60000}}}
	for i := 0; i < 2; i++ {
		call := c.expect(t, "DeviceCall", func(m *pb.ControlMessage) bool { return m.GetDeviceCall() != nil }).GetDeviceCall()
		c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(),
			Class: pb.ResultClass_DONE, HttpStatus: 401, DpopNonce: "n" + strings.Repeat("x", i)}}}
	}
	select {
	case <-h.hb.nonces:
	case <-time.After(5 * time.Second):
		t.Fatal("no HTTPS fallback after two nonce refusals")
	}
	select {
	case m := <-c.sent:
		if m.GetDeviceCall() != nil {
			t.Fatal("third stream 0 call")
		}
	default:
	}
}

func TestCallIDsWrap(t *testing.T) {
	m := &Manager{calls: map[uint32]chan *pb.DeviceResult{}, callID: 1<<31 - 2}
	a, _ := m.register()
	b, _ := m.register()
	if a != 1<<31-1 || b != 1 {
		t.Fatal(a, b)
	}
}

func TestSameTimeSignedStateAccepted(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000100), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	h.wait("first", func(s Status) bool { return s.SignedTime == 1700000100 })
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "revoked", "active", 1700000100), "")
	})
	h.advance(5 * time.Minute)
	h.wait("same-second state applied", func(s Status) bool { return s.Hold == ladder.HoldRevoked })
}

func TestSinceFollowsTransitions(t *testing.T) {
	h := newHarness(t)
	start := h.wait("start", func(s Status) bool { return !s.Since.IsZero() }).Since
	h.advance(3 * time.Second)
	h.fail(h.dial(), "dial")
	s := h.wait("reconnecting", func(s Status) bool { return s.State == ladder.Reconnecting })
	if !s.Since.After(start) {
		t.Fatalf("since not moved: %v %v", start, s.Since)
	}
	h.advance(time.Second)
	if h.m.Status().Since != s.Since {
		t.Fatal("since moved without a transition")
	}
}

func TestAnswerSizeBoundary(t *testing.T) {
	body := answerJSON("s", "")
	exact := body + strings.Repeat(" ", maxAnswer-len(body))
	if _, err := parseAnswer([]byte(exact)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAnswer([]byte(exact + " ")); err == nil {
		t.Fatal("over the cap accepted")
	}
}

func TestFlagsFileGenerationOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveFlags(dir, 1, true, "doc"); err != nil {
		t.Fatal(err)
	}
	if f, err := loadFlags(dir); err != nil || f.generation != 1 {
		t.Fatal(f, err)
	}
}

func TestHoldHeartbeatRepeats(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000001), flagsDoc(t, 3, "off"))
	})
	h.refuse(h.dial(), pb.RefuseCode_PROTOCOL_DISABLED)
	<-h.hb.nonces
	h.wait("flags off", func(s Status) bool { return s.Hold == ladder.HoldFlagsOff })
	for i := 0; i < 3; i++ {
		h.advance(5 * time.Minute)
		select {
		case <-h.hb.nonces:
		case <-time.After(5 * time.Second):
			t.Fatalf("heartbeat %d in HOLD missing", i+1)
		}
	}
}

func TestTimerJitterDrawnOncePerWindow(t *testing.T) {
	var mu sync.Mutex
	draws := 0
	h := newHarness(t, func(c *Config) {
		c.Rand = func(n int64) int64 {
			mu.Lock()
			draws++
			mu.Unlock()
			return n - 1
		}
	})
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000001), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_PROTOCOL_DISABLED)
	h.wait("maintenance", func(s Status) bool { return s.Hold == ladder.HoldMaintenance })
	h.wait("heartbeat answer", func(s Status) bool { return s.SignedTime == 1700000001 })
	mu.Lock()
	before := draws
	mu.Unlock()
	h.net <- struct{}{}
	h.settle()
	h.advance(NetworkSettle)
	h.settle()
	mu.Lock()
	after := draws
	mu.Unlock()
	if after != before {
		t.Fatalf("unchanged windows drawn again: %d -> %d", before, after)
	}
}
