package session

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

type hookCall struct {
	ctx context.Context
	ds  DataSession
}

func withStreams(calls chan hookCall, ended *sync.WaitGroup) option {
	return func(c *Config) {
		c.Streams = func(ctx context.Context, ds DataSession) {
			ended.Add(1)
			defer ended.Done()
			calls <- hookCall{ctx, ds}
			<-ctx.Done()
		}
	}
}

func nextCall(t *testing.T, calls chan hookCall) hookCall {
	t.Helper()
	select {
	case c := <-calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("stream hook not called")
		return hookCall{}
	}
}

func TestStreamsHookPerSession(t *testing.T) {
	calls := make(chan hookCall, 4)
	var ended sync.WaitGroup
	h := newHarness(t, withStreams(calls, &ended))
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	c.info.Capabilities = []string{"x"}
	c.info.MaxStreams = 64
	r.reply <- dialRes{conn: c}
	call := nextCall(t, calls)
	if call.ds.Routes() != nil {
		t.Fatal("routes before the first RouteSet")
	}
	if call.ds.EdgeID != testEdge || call.ds.MaxStreams != 64 || len(call.ds.Capabilities) != 1 || call.ds.Capabilities[0] != "x" {
		t.Fatalf("%+v", call.ds)
	}
	c.in <- routeSetMsg(t, 1, testSessionID)
	c.expect(t, "RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 1 })
	rs := call.ds.Routes()
	if rs == nil || rs.Version != 1 || rs.SessionID == "" || len(rs.Routes) != 1 {
		t.Fatalf("%+v", rs)
	}
	c.in <- routeSetMsg(t, 2, testSessionID)
	c.expect(t, "RouteSetAck 2", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 2 })
	if call.ds.Routes().Version != 2 {
		t.Fatal("routes not updated")
	}
	select {
	case <-call.ctx.Done():
		t.Fatal("context ended while the session is open")
	default:
	}
	_ = c.Close()
	select {
	case <-call.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context not cancelled when the session closed")
	}
	if rs := call.ds.Routes(); rs == nil || rs.Version != 2 {
		t.Fatal("routes of a closed session changed")
	}
}

func TestStreamsHookRoutesAreTheSessionsOwn(t *testing.T) {
	calls := make(chan hookCall, 4)
	var ended sync.WaitGroup
	h := newHarness(t, withStreams(calls, &ended))
	r := h.dial()
	first := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: first}
	one := nextCall(t, calls)
	first.in <- routeSetMsg(t, 3, testSessionID)
	first.expect(t, "RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 3 })
	_ = first.Close()
	h.wait("down", func(s Status) bool { return !s.Up })
	h.advance(5 * time.Second)
	r = h.dial()
	second := newConn(r.carriage, h.clock)
	second.info.SessionID = []byte("fedcba9876543210")
	r.reply <- dialRes{conn: second}
	two := nextCall(t, calls)
	if two.ds.Routes() != nil {
		t.Fatal("a new session sees an old session's routes")
	}
	second.in <- routeSetMsg(t, 1, []byte("fedcba9876543210"))
	second.expect(t, "RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 1 })
	if one.ds.Routes().Version != 3 || two.ds.Routes().Version != 1 {
		t.Fatal(one.ds.Routes(), two.ds.Routes())
	}
}

func TestStreamsHookEndsWithTheManager(t *testing.T) {
	calls := make(chan hookCall, 4)
	var ended sync.WaitGroup
	h := newHarness(t, withStreams(calls, &ended))
	h.up(h.dial())
	call := nextCall(t, calls)
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not stop")
	}
	select {
	case <-call.ctx.Done():
	default:
		t.Fatal("hook context still live after Run returned")
	}
	ended.Wait()
}

func TestSignedClockFromRouteSet(t *testing.T) {
	sc := NewSignedClock(func() time.Time { return time.Unix(1600000000, 0) })
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	m := routeSetMsg(t, 1, testSessionID)
	m.GetRouteSet().SignedTime = sign(t, "control", protocol.TypTime, map[string]any{"server_id": testServer, "time": 1700000500, "nonce": claims.TimeNonce(c.info.TimeNonce)})
	c.in <- m
	h.wait("signed time", func(s Status) bool { return s.SignedTime == 1700000500 })
	if got := sc.Now().Unix(); got != 1700000500 {
		t.Fatal(got)
	}
}

func TestSignedClockFromHeartbeat(t *testing.T) {
	sc := NewSignedClock(func() time.Time { return time.Unix(1900000000, 0) })
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000100), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	h.wait("time", func(s Status) bool { return s.SignedTime == 1700000100 })
	if got := sc.Now().Unix(); got != 1700000100 {
		t.Fatal("a clock ahead of signed time is not corrected:", got)
	}
}

func takeEnded(t *testing.T, ds DataSession) []string {
	t.Helper()
	select {
	case <-ds.Ended.C():
		return ds.Ended.Take()
	case <-time.After(5 * time.Second):
		t.Fatal("no app ended")
		return nil
	}
}

func routeSetApps(t testing.TB, version int64, apps ...string) *pb.ControlMessage {
	var routes []map[string]any
	for i, a := range apps {
		routes = append(routes, map[string]any{"app_id": a, "fqdn": fmt.Sprintf("app%d.example.seawise.dev", i), "public": false, "access_version": 1})
	}
	if routes == nil {
		routes = []map[string]any{}
	}
	c := map[string]any{"edge": testEdge, "server_id": testServer, "session_id": base64.RawURLEncoding.EncodeToString(testSessionID),
		"version": version, "iat": 1700000000, "routes": routes}
	return &pb.ControlMessage{Body: &pb.ControlMessage_RouteSet{RouteSet: &pb.RouteSet{Jws: sign(t, testEdge, protocol.TypRouteSet, c)}}}
}

func TestStreamsHookAppEnds(t *testing.T) {
	const appX, appY = "11111111-2222-4333-8444-555555555555", "11111111-2222-4333-8444-666666666666"
	calls := make(chan hookCall, 4)
	var ended sync.WaitGroup
	h := newHarness(t, withStreams(calls, &ended))
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	call := nextCall(t, calls)
	c.in <- routeSetApps(t, 1, appX, appY)
	c.expect(t, "RouteSetAck", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 1 })
	c.in <- routeSetApps(t, 2, appY)
	c.expect(t, "RouteSetAck 2", func(m *pb.ControlMessage) bool { return m.GetRouteSetAck().GetVersion() == 2 })
	if got := takeEnded(t, call.ds); len(got) != 1 || got[0] != appX {
		t.Fatalf("removed app not ended: %v", got)
	}
	idY, _ := hex.DecodeString(strings.ReplaceAll(appY, "-", ""))
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Revoke{Revoke: &pb.Revoke{Scope: pb.RevokeScope_APP, AppId: idY}}}
	if got := takeEnded(t, call.ds); len(got) != 1 || got[0] != appY {
		t.Fatalf("revoked app not ended: %v", got)
	}
}
