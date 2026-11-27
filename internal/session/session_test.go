package session

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/transport"
)

func isPing(m *pb.ControlMessage) bool { return m.GetPing() != nil }

func TestStartDialsRawTLSAndAppliesRoutes(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	if r.carriage != transport.TLS {
		t.Fatalf("first dial over %s", r.carriage)
	}
	c := h.up(r)
	s := h.m.Status()
	if s.State != ladder.Own || s.Carriage != "tls" || s.Edge != testEdge || !s.Up {
		t.Fatalf("%+v", s)
	}
	select {
	case rs := <-h.routes:
		if rs.Version != 1 || len(rs.Routes) != 1 {
			t.Fatal(rs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("routes not applied")
	}
	c.in <- routeSetMsg(t, 2, testSessionID)
	c.expect(t, "second RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 2 })
	<-h.routes
}

func TestNoRouteSetAfterHelloAckIsADialFailure(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	h.settle()
	h.advance(RouteSetDeadline)
	h.wait("reconnecting", func(s Status) bool { return s.State == ladder.Reconnecting && !s.Up })
	if !c.isClosed() {
		t.Fatal("session without RouteSet left open")
	}
	h.advance(time.Second)
	if r := h.dial(); r.carriage != transport.TLS {
		t.Fatal(r.carriage)
	}
}

func TestRouteSetRefusals(t *testing.T) {
	for name, msg := range map[string]func(t *testing.T) *pb.ControlMessage{
		"other session": func(t *testing.T) *pb.ControlMessage { return routeSetMsg(t, 1, []byte("fedcba9876543210")) },
		"unsigned": func(t *testing.T) *pb.ControlMessage {
			return &pb.ControlMessage{Body: &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: "a.b.c"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r := h.dial()
			c := newConn(r.carriage, h.clock)
			r.reply <- dialRes{conn: c}
			c.in <- msg(t)
			h.wait("reconnecting", func(s Status) bool { return s.State == ladder.Reconnecting })
			if !c.isClosed() {
				t.Fatal("left open")
			}
		})
	}
}

func TestCarriageFlipsToWebSocketAndReprobesTLS(t *testing.T) {
	h := newHarness(t)
	h.fail(h.dial(), transport.CauseTLS)
	h.advance(time.Second)
	h.fail(h.dial(), transport.CauseTLS)
	h.advance(2 * time.Second)
	r := h.dial()
	if r.carriage != transport.WebSocket {
		t.Fatalf("third dial over %s", r.carriage)
	}
	ws := h.up(r)
	if s := h.m.Status(); s.State != ladder.OwnWS || s.Carriage != "websocket" {
		t.Fatalf("%+v", s)
	}
	h.advance(15 * time.Minute)
	probe := h.dial()
	if probe.carriage != transport.TLS {
		t.Fatalf("re-probe over %s", probe.carriage)
	}
	tls := newConn(transport.TLS, h.clock)
	probe.reply <- dialRes{conn: tls}
	tls.in <- routeSetMsg(t, 1, testSessionID)
	h.wait("back on TLS", func(s Status) bool { return s.State == ladder.Own && s.Carriage == "tls" })
	if ws.isClosed() {
		t.Fatal("WebSocket session closed before its grace")
	}
	h.advance(ReprobeGrace)
	for i := 0; !ws.isClosed() && i < 500; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if !ws.isClosed() || tls.isClosed() {
		t.Fatal("old session not retired or new one closed")
	}
}

func TestFailedReprobeKeepsWebSocket(t *testing.T) {
	h := newHarness(t)
	h.fail(h.dial(), transport.CauseDial)
	h.advance(time.Second)
	h.fail(h.dial(), transport.CauseDial)
	h.advance(2 * time.Second)
	ws := h.up(h.dial())
	h.advance(15 * time.Minute)
	h.fail(h.dial(), transport.CauseTLS)
	h.wait("still on WebSocket", func(s Status) bool { return s.State == ladder.OwnWS && s.Up })
	h.advance(15 * time.Minute)
	h.noDial(20 * time.Millisecond)
	h.advance(15 * time.Minute)
	if r := h.dial(); r.carriage != transport.TLS {
		t.Fatal(r.carriage)
	}
	if ws.isClosed() {
		t.Fatal("failed re-probe closed the session")
	}
}

func TestLivenessPingsThenDropsSilentSession(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.setRx(h.clock.Now())
	h.advance(19 * time.Second)
	c.setRx(h.clock.Now())
	h.advance(10 * time.Second)
	select {
	case m := <-c.sent:
		if isPing(m) {
			t.Fatal("pinged although bytes arrived")
		}
	default:
	}
	h.advance(10 * time.Second)
	c.expect(t, "Ping", isPing)
	h.advance(15 * time.Second)
	h.wait("silent session dropped", func(s Status) bool { return s.State == ladder.Reconnecting && !s.Up })
	if !c.isClosed() {
		t.Fatal("silent session left open")
	}
	if r := h.dial(); r.carriage != transport.TLS {
		t.Fatal(r.carriage)
	}
}

func TestPongKeepsSession(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.setRx(h.clock.Now())
	h.advance(20 * time.Second)
	c.expect(t, "Ping", isPing)
	c.setRx(h.clock.Now())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Pong{Pong: &pb.Pong{Nonce: 1}}}
	h.advance(16 * time.Second)
	if s := h.m.Status(); !s.Up || c.isClosed() {
		t.Fatalf("answered session dropped: %+v", s)
	}
}

func TestSessionLossRedialsAtOnce(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	_ = c.Close()
	h.wait("reconnecting", func(s Status) bool { return s.State == ladder.Reconnecting })
	if r := h.dial(); r.carriage != transport.TLS {
		t.Fatal(r.carriage)
	}
}

func TestBackoffCappedAndNeverGivesUp(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Rand = func(n int64) int64 { return n - 1 } })
	for i := 0; i < 12; i++ {
		r := h.dial()
		h.refuse(r, pb.RefuseCode_OVERLOADED)
		s := h.wait("next dial scheduled", func(s Status) bool { return !s.NextDial.IsZero() && s.State == ladder.Reconnecting })
		if d := s.NextDial.Sub(h.clock.Now()); d > 30*time.Second {
			t.Fatalf("backoff %s over 30 s", d)
		}
		h.advance(30 * time.Second)
	}
	if s := h.m.Status(); s.Carriage != "tls" {
		t.Fatalf("refusals flipped the carriage: %+v", s)
	}
}

func TestRetryAfterHonoured(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	r.reply <- dialRes{err: &transport.Error{Kind: transport.Transient, Code: pb.RefuseCode_OVERLOADED, RetryAfter: 10 * time.Second}}
	h.settle()
	h.advance(9 * time.Second)
	h.noDial(20 * time.Millisecond)
	h.advance(time.Second + ladder.RedialCap)
	h.dial()
}

func TestLocalErrorsNeverReachTheLadder(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		r := h.dial()
		r.reply <- dialRes{err: &transport.Error{Kind: transport.Local, Reason: "edge_list"}}
		at := h.clock.Now().Add(LocalRetry)
		s := h.wait("local retry", func(s Status) bool { return s.NextDial.Equal(at) })
		if s.State != ladder.Own || s.Carriage != "tls" || s.LastError != "local: edge_list" {
			t.Fatalf("local error moved the ladder: %+v", s)
		}
		h.advance(LocalRetry - time.Second)
		h.noDial(20 * time.Millisecond)
		h.advance(time.Second)
	}
	h.up(h.dial())
}

func TestUpdateRequiredHoldsWithSlowRedial(t *testing.T) {
	for name, fail := range map[string]func(h *harness, r dialReq){
		"version too old": func(h *harness, r dialReq) { h.refuse(r, pb.RefuseCode_VERSION_TOO_OLD) },
		"edge too old":    func(h *harness, r dialReq) { h.fail(r, transport.CauseEdgeTooOld) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			fail(h, h.dial())
			s := h.wait("hold", func(s Status) bool { return s.Hold == ladder.HoldUpdate })
			if s.HoldText != "update required" || s.Up {
				t.Fatalf("%+v", s)
			}
			<-h.hb.nonces
			h.advance(14 * time.Minute)
			h.noDial(20 * time.Millisecond)
			h.advance(time.Minute)
			h.dial()
		})
	}
}

func TestTwoSubprotocolRefusalsHold(t *testing.T) {
	h := newHarness(t)
	h.fail(h.dial(), transport.CauseSubprotocol)
	h.advance(time.Second)
	h.fail(h.dial(), transport.CauseSubprotocol)
	h.wait("hold", func(s Status) bool { return s.Hold == ladder.HoldUpdate })
}

func TestForgedALPNAlertsNeverHold(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 6; i++ {
		h.fail(h.dial(), transport.CauseALPN)
		h.wait("reconnecting", func(s Status) bool { return s.State == ladder.Reconnecting })
		h.advance(30 * time.Second)
	}
	if s := h.m.Status(); s.Hold != "" {
		t.Fatal(s)
	}
}

func TestMaintenanceHoldLeftByNewerFlagsOn(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000001), flagsDoc(t, 5, "on"))
	})
	h.refuse(h.dial(), pb.RefuseCode_PROTOCOL_DISABLED)
	<-h.hb.nonces
	h.wait("left maintenance", func(s Status) bool { return s.State == ladder.Reconnecting && s.FlagsGeneration == 5 })
	h.advance(30 * time.Second)
	h.dial()
}

func TestFlagsOffOverHeartbeatHoldsAndPersists(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000001), flagsDoc(t, 7, "off"))
	})
	h.refuse(h.dial(), pb.RefuseCode_PROTOCOL_DISABLED)
	s := h.wait("flags off", func(s Status) bool { return s.Hold == ladder.HoldFlagsOff })
	if s.HoldText != "maintenance" || s.FlagsMode != "OFF" {
		t.Fatal(s)
	}
	f, err := loadFlags(h.dir)
	if err != nil || f.generation != 7 || f.on {
		t.Fatal(f, err)
	}
	h.advance(4 * time.Hour)
	select {
	case r := <-h.dials:
		t.Fatalf("dialled under flags off over %s", r.carriage)
	default:
	}
}

func TestPersistedFlagsOffHoldsAtStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveFlags(dir, 3, false, flagsDoc(t, 3, "off")); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *Config) { c.DataDir = dir })
	h.wait("flags off at start", func(s Status) bool { return s.Hold == ladder.HoldFlagsOff })
	h.noDial(20 * time.Millisecond)
	h.advance(5 * time.Minute)
	<-h.hb.nonces
}

func TestFlagsOnStream0KillSwitchAndRollback(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	pv := func(v uint64, doc string) {
		c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: v, Flags: doc}}}
	}
	pv(1, flagsDoc(t, 4, "on"))
	h.wait("generation 4", func(s Status) bool { return s.FlagsGeneration == 4 && s.Up })
	pv(2, flagsDoc(t, 4, "on"))
	pv(3, flagsDoc(t, 3, "off"))
	h.wait("rollback refused", func(s Status) bool { return s.FlagsRollbacks == 1 })
	if s := h.m.Status(); !s.Up || s.Hold != "" {
		t.Fatalf("rollback acted: %+v", s)
	}
	pv(4, flagsDoc(t, 9, "off"))
	h.wait("kill switch", func(s Status) bool { return s.Hold == ladder.HoldFlagsOff && !s.Up })
	if !c.isClosed() {
		t.Fatal("session left open under flags off")
	}
}

func TestPolicyVersionMustIncrease(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 2}}}
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 2}}}
	h.wait("dropped", func(s Status) bool { return s.State == ladder.Reconnecting })
}

func TestUnsignedFlagsIgnored(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	doc := sign(t, testEdge, "sw-tunnel-flags+jws", map[string]any{"generation": 9})
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_PolicyVersion{PolicyVersion: &pb.PolicyVersion{Version: 1, Flags: doc}}}
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Pong{Pong: &pb.Pong{}}}
	time.Sleep(20 * time.Millisecond)
	if s := h.m.Status(); !s.Up || s.FlagsGeneration != 0 {
		t.Fatal(s)
	}
}

func TestRevokeIsASessionDropUntilConfirmed(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) { return http.StatusServiceUnavailable, "" })
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Revoke{Revoke: &pb.Revoke{Scope: pb.RevokeScope_DEVICE}}}
	<-h.hb.nonces
	s := h.wait("dropped", func(s Status) bool { return s.State == ladder.Reconnecting })
	if s.Hold != "" || !c.isClosed() {
		t.Fatalf("unsigned revoke held: %+v", s)
	}
	h.dial()
}

func TestSignedStateHoldsAndClears(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "revoked", "active", 1700000010), "")
	})
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Revoke{Revoke: &pb.Revoke{Scope: pb.RevokeScope_DEVICE}}}
	s := h.wait("revoked", func(s Status) bool { return s.Hold == ladder.HoldRevoked })
	if s.HoldText != "device revoked" {
		t.Fatal(s)
	}
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000020), "")
	})
	h.advance(5 * time.Minute)
	h.wait("cleared", func(s Status) bool { return s.State == ladder.Reconnecting })
	h.advance(30 * time.Second)
	h.dial()
}

func TestSuspendedAccountHolds(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "suspended", 1700000010), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_ACCOUNT_SUSPENDED)
	s := h.wait("suspended", func(s Status) bool { return s.Hold == ladder.HoldSuspended })
	if s.HoldText != "account suspended" {
		t.Fatal(s)
	}
}

func TestSignedStateBindingRefused(t *testing.T) {
	for name, tok := range map[string]func(t *testing.T, n string) string{
		"other nonce": func(t *testing.T, n string) string {
			return stateTok(t, "AAAAAAAAAAAAAAAAAAAAAA", "revoked", "active", 1)
		},
		"other key": func(t *testing.T, n string) string {
			return sign(t, "control", "sw-state+jwt", map[string]any{"server_id": testServer, "key_id": "B" + deviceKeyID()[1:],
				"time": 1, "nonce": n, "device_status": "revoked", "account_status": "active"})
		},
		"edge signed": func(t *testing.T, n string) string {
			return sign(t, testEdge, "sw-state+jwt", map[string]any{"server_id": testServer, "key_id": deviceKeyID(),
				"time": 1, "nonce": n, "device_status": "revoked", "account_status": "active"})
		},
		"time only": func(t *testing.T, n string) string {
			return sign(t, "control", "sw-time+jwt", map[string]any{"server_id": testServer, "time": 1, "nonce": n})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.hb.set(func(n string) (int, string) { return http.StatusOK, answerJSON(tok(t, n), "") })
			h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
			<-h.hb.nonces
			time.Sleep(20 * time.Millisecond)
			if s := h.m.Status(); s.Hold != "" || s.State != ladder.Reconnecting {
				t.Fatalf("held on a refused state: %+v", s)
			}
		})
	}
}

func TestOlderSignedStateIgnored(t *testing.T) {
	h := newHarness(t)
	at := int64(1700000100)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", at), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	h.wait("time", func(s Status) bool { return s.SignedTime == at })
	at = 1700000050
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "revoked", "active", at), "")
	})
	h.advance(5 * time.Minute)
	<-h.hb.nonces
	<-h.hb.nonces
	time.Sleep(20 * time.Millisecond)
	if s := h.m.Status(); s.Hold != "" {
		t.Fatalf("older state applied: %+v", s)
	}
}

func TestDrainReconnectMakesBeforeBreak(t *testing.T) {
	h := newHarness(t)
	old := h.up(h.dial())
	old.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_MAX_AGE, Action: pb.DrainAction_RECONNECT, DeadlineMs: 120000}}}
	r := h.dial()
	if r.carriage != transport.TLS {
		t.Fatal(r.carriage)
	}
	if old.isClosed() {
		t.Fatal("old session closed before the new one")
	}
	nc := newConn(r.carriage, h.clock)
	nc.info.SessionID = []byte("fedcba9876543210")
	r.reply <- dialRes{conn: nc}
	nc.in <- routeSetMsg(t, 1, nc.info.SessionID)
	h.wait("switched", func(s Status) bool { return s.Up && s.SessionID == "ZmVkY2JhOTg3NjU0MzIxMA" })
	h.advance(119 * time.Second)
	if old.isClosed() {
		t.Fatal("old session closed before its deadline")
	}
	h.advance(2 * time.Second)
	for i := 0; !old.isClosed() && i < 500; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if !old.isClosed() {
		t.Fatal("old session not closed at its deadline")
	}
}

func TestDrainSupersededPauses(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_SUPERSEDED, Action: pb.DrainAction_HOLD, DeadlineMs: 1000}}}
	s := h.wait("superseded", func(s Status) bool { return s.Supersedes == 1 && s.State == ladder.Reconnecting })
	if s.Hold != "" {
		t.Fatal(s)
	}
	h.advance(59 * time.Second)
	h.noDial(20 * time.Millisecond)
	h.advance(time.Second)
	h.dial()
}

func TestNetworkChangeResetsCarriage(t *testing.T) {
	h := newHarness(t)
	h.fail(h.dial(), transport.CauseDial)
	h.advance(time.Second)
	h.fail(h.dial(), transport.CauseDial)
	h.wait("websocket next", func(s Status) bool { return s.Carriage == "websocket" })
	h.net <- struct{}{}
	h.settle()
	h.advance(NetworkSettle)
	if r := h.dial(); r.carriage != transport.TLS {
		t.Fatalf("after a network change: %s", r.carriage)
	}
}

func TestRepairNeededHolds(t *testing.T) {
	h := newHarness(t)
	h.up(h.dial())
	h.m.RepairNeeded()
	s := h.wait("repair", func(s Status) bool { return s.Hold == ladder.HoldRepair })
	if s.Up || s.HoldText != "repair needed" {
		t.Fatal(s)
	}
}

func TestStreamZeroHeartbeat(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_KILL_SWITCH, Action: pb.DrainAction_HOLD, DeadlineMs: 60000}}}
	m := c.expect(t, "DeviceCall", func(m *pb.ControlMessage) bool { return m.GetDeviceCall() != nil })
	call := m.GetDeviceCall()
	if call.GetMethod() != pb.DeviceMethod_SIGNED_TIME || len(call.GetIdempotencyKey()) != 16 || call.GetDpop() == "" {
		t.Fatal(call)
	}
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(),
		Class: pb.ResultClass_DONE, HttpStatus: 401, DpopNonce: "fresh-nonce"}}}
	m = c.expect(t, "retried DeviceCall", func(m *pb.ControlMessage) bool { return m.GetDeviceCall() != nil })
	retry := m.GetDeviceCall()
	if string(retry.GetIdempotencyKey()) != string(call.GetIdempotencyKey()) {
		t.Fatal("retry changed the idempotency key")
	}
	var body struct {
		Nonce string `json:"nonce"`
	}
	_ = jsonDecode(retry.GetBody(), &body)
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: retry.GetCallId(),
		Class: pb.ResultClass_DONE, HttpStatus: 200,
		Body: []byte(answerJSON(stateTok(t, body.Nonce, "active", "active", 1700000001), flagsDoc(t, 2, "off")))}}}
	h.wait("flags off from stream 0", func(s Status) bool { return s.Hold == ladder.HoldFlagsOff })
	select {
	case n := <-h.hb.nonces:
		t.Fatalf("HTTPS used although stream 0 answered: %s", n)
	default:
	}
}

func TestStreamZeroUnavailableFallsBackToHTTPS(t *testing.T) {
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) { return http.StatusServiceUnavailable, "" })
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_KILL_SWITCH, Action: pb.DrainAction_HOLD, DeadlineMs: 60000}}}
	call := c.expect(t, "DeviceCall", func(m *pb.ControlMessage) bool { return m.GetDeviceCall() != nil }).GetDeviceCall()
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(), Class: pb.ResultClass_UNAVAILABLE}}}
	select {
	case <-h.hb.nonces:
	case <-time.After(5 * time.Second):
		t.Fatal("no HTTPS heartbeat")
	}
	if s := h.m.Status(); !s.Up {
		t.Fatal("UNAVAILABLE changed state", s)
	}
}

func TestStopClosesEverything(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	h.cancel()
	select {
	case <-h.done:
		h.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop")
	}
	if !c.isClosed() {
		t.Fatal("session left open")
	}
}

func TestFlagsFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if f, err := loadFlags(dir); err != nil || !f.on || f.generation != 0 {
		t.Fatal(f, err)
	}
	for _, bad := range []string{`{`, `{"schema":2,"generation":1,"mode":"ON"}`, `{"schema":1,"generation":0,"mode":"ON"}`, `{"schema":1,"generation":1,"mode":"on"}`} {
		if err := os.WriteFile(filepath.Join(dir, FlagsFile), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if f, err := loadFlags(dir); err == nil || !f.on || f.generation != 0 {
			t.Errorf("%s: %v %v", bad, f, err)
		}
	}
	if err := saveFlags(dir, 4, false, "doc"); err != nil {
		t.Fatal(err)
	}
	if f, err := loadFlags(dir); err != nil || f.on || f.generation != 4 {
		t.Fatal(f, err)
	}
	if f, err := loadFlags(""); err != nil || !f.on || saveFlags("", 1, false, "") != nil {
		t.Fatal(f, err)
	}
}

func TestHoldTexts(t *testing.T) {
	for reason, text := range map[string]string{
		ladder.HoldUpdate: "update required", ladder.HoldMaintenance: "maintenance", ladder.HoldFlagsOff: "maintenance",
		ladder.HoldTooManyRoutes: "too many apps", ladder.HoldRevoked: "device revoked", ladder.HoldSuspended: "account suspended",
		ladder.HoldRepair: "repair needed", "": "",
	} {
		if got := HoldText(reason); got != text {
			t.Errorf("%s: %q", reason, got)
		}
	}
}

func TestNewValidates(t *testing.T) {
	good := Config{Dial: func() DialFunc { return nil }(), Name: testName, ServerID: testServer}
	if _, err := New(good); err == nil {
		t.Fatal("accepted without dial")
	}
	h := newHarness(t)
	cfg := h.m.cfg
	cfg.ServerID = "3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B"
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted a non-canonical server id")
	}
	cfg.ServerID, cfg.Name = testServer, ""
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted without a name")
	}
}

func TestUnsignedRetryAfterCapped(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	r.reply <- dialRes{err: &transport.Error{Kind: transport.Transient, Code: pb.RefuseCode_OVERLOADED, RetryAfter: (1<<32 - 1) * time.Millisecond}}
	h.settle()
	s := h.wait("scheduled", func(s Status) bool { return !s.NextDial.IsZero() })
	if d := s.NextDial.Sub(h.clock.Now()); d > ladder.ReprobeCap+ladder.RedialCap || d < ladder.ReprobeCap+ladder.RedialCap-time.Second {
		t.Fatalf("parked for %s", d)
	}
	h.advance(ladder.ReprobeCap + ladder.RedialCap)
	h.dial()
}

func drainMsg(ms uint32) *pb.ControlMessage {
	return &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_REBALANCE, Action: pb.DrainAction_RECONNECT, DeadlineMs: ms}}}
}

func TestDrainDeadlineClamped(t *testing.T) {
	h := newHarness(t)
	old := h.up(h.dial())
	old.in <- drainMsg(1<<32 - 1)
	nc := newConn(transport.TLS, h.clock)
	nc.info.SessionID = []byte("fedcba9876543210")
	h.dial().reply <- dialRes{conn: nc}
	nc.in <- routeSetMsg(t, 1, nc.info.SessionID)
	h.wait("switched", func(s Status) bool { return s.SessionID == "ZmVkY2JhOTg3NjU0MzIxMA" })
	h.advance(121 * time.Second)
	for i := 0; !old.isClosed() && i < 500; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	if !old.isClosed() {
		t.Fatal("drained session kept past 120 s")
	}
}

func TestRepeatedDrainsKeepFewRetiredSessions(t *testing.T) {
	h := newHarness(t)
	conns := []*fakeConn{h.up(h.dial())}
	for i := 0; i < 6; i++ {
		conns[len(conns)-1].in <- drainMsg(120000)
		nc := newConn(transport.TLS, h.clock)
		nc.info.SessionID = []byte(fmt.Sprintf("session-%08d", i))
		h.dial().reply <- dialRes{conn: nc}
		nc.in <- routeSetMsg(t, 1, nc.info.SessionID)
		want := base64.RawURLEncoding.EncodeToString(nc.info.SessionID)
		h.wait("switched", func(s Status) bool { return s.SessionID == want })
		conns = append(conns, nc)
	}
	open := 0
	for _, c := range conns[:len(conns)-1] {
		if !c.isClosed() {
			open++
		}
	}
	if open != maxRetired {
		t.Fatalf("%d retired sessions open", open)
	}
	for _, c := range conns[len(conns)-1-maxRetired : len(conns)-1] {
		if c.isClosed() {
			t.Fatal("a newer retired session closed before an older one")
		}
	}
}

func TestStoredFlagsReverifiedAtStart(t *testing.T) {
	for name, doc := range map[string]func(t *testing.T) string{
		"not a JWS": func(*testing.T) string { return "x" },
		"edge signed": func(t *testing.T) string {
			return sign(t, testEdge, protocol.TypFlags, map[string]any{"generation": 3})
		},
		"other generation":    func(t *testing.T) string { return flagsDoc(t, 4, "off") },
		"mode does not match": func(t *testing.T) string { return flagsDoc(t, 3, "on") },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := saveFlags(dir, 3, false, doc(t)); err != nil {
				t.Fatal(err)
			}
			h := newHarness(t, func(c *Config) { c.DataDir = dir })
			h.dial()
			if s := h.m.Status(); s.Hold != "" || s.FlagsGeneration != 0 || s.FlagsMode != "ON" {
				t.Fatalf("unverified stored flags used: %+v", s)
			}
		})
	}
}

func TestSupersededCancelsDialsInFlight(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	c.in <- drainMsg(120000)
	second := h.dial()
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_SUPERSEDED, Action: pb.DrainAction_HOLD, DeadlineMs: 1000}}}
	h.wait("superseded", func(s Status) bool { return s.Supersedes == 1 })
	nc := newConn(transport.TLS, h.clock)
	nc.info.SessionID = []byte("fedcba9876543210")
	second.reply <- dialRes{conn: nc}
	nc.in <- routeSetMsg(t, 1, nc.info.SessionID)
	h.settle()
	if s := h.m.Status(); s.Up {
		t.Fatalf("pause bypassed by a dial in flight: %+v", s)
	}
	for i := 0; !nc.isClosed() && i < 500; i++ {
		time.Sleep(2 * time.Millisecond)
	}
	// A cancelled dial may never take the session; one it took is closed.
	if !nc.isClosed() && len(second.reply) == 0 {
		t.Fatal("late session left open")
	}
}

func TestNetworkDialsRateLimited(t *testing.T) {
	h := newHarness(t)
	h.fail(h.dial(), transport.CauseDial)
	h.advance(time.Second)
	h.dial()
	h.net <- struct{}{}
	h.settle()
	h.advance(NetworkSettle)
	h.dial()
	h.net <- struct{}{}
	h.settle()
	h.advance(NetworkSettle)
	h.noDial(20 * time.Millisecond)
	h.advance(NetworkDialEvery)
	h.dial()
}
