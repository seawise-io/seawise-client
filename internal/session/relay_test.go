package session

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/transport"
)

func deviceCall() *pb.DeviceCall {
	return &pb.DeviceCall{IdempotencyKey: make([]byte, 16), Method: pb.DeviceMethod_LIST_APPS, Dpop: "a.b.c"}
}

type relayed struct {
	r   *pb.DeviceResult
	err error
}

func relayAsync(m *Manager, ctx context.Context) chan relayed {
	out := make(chan relayed, 1)
	go func() {
		r, err := m.Relay(ctx, deviceCall())
		out <- relayed{r, err}
	}()
	return out
}

func waitRelay(t *testing.T, ch chan relayed) relayed {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
		return relayed{}
	}
}

func sentCall(t *testing.T, c *fakeConn) *pb.DeviceCall {
	t.Helper()
	return c.expect(t, "DeviceCall", func(m *pb.ControlMessage) bool { return m.GetDeviceCall() != nil }).GetDeviceCall()
}

func noCall(t *testing.T, c *fakeConn) {
	t.Helper()
	for {
		select {
		case m := <-c.sent:
			if m.GetDeviceCall() != nil {
				t.Fatal("device call sent")
			}
		default:
			return
		}
	}
}

// Without a session whose RouteSet verified, nothing is sent on stream 0.
func TestRelayNeedsAnUpSession(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.Relay(context.Background(), deviceCall()); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	h.settle()
	if _, err := h.m.Relay(context.Background(), deviceCall()); !errors.Is(err, ErrNoSession) {
		t.Fatal("call relayed before the RouteSet verified:", err)
	}
	noCall(t, c)
	c.in <- routeSetMsg(t, 1, testSessionID)
	h.wait("up", func(s Status) bool { return s.Up })
	ch := relayAsync(h.m, context.Background())
	call := sentCall(t, c)
	if call.GetCallId() == 0 || call.GetMethod() != pb.DeviceMethod_LIST_APPS {
		t.Fatal(call)
	}
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(), Class: pb.ResultClass_DONE, HttpStatus: 200, Body: []byte("{}")}}}
	got := waitRelay(t, ch)
	if got.err != nil || got.r.GetHttpStatus() != 200 || string(got.r.GetBody()) != "{}" {
		t.Fatal(got)
	}
}

// A session that ends mid-call fails the call at once: its outcome is
// unknown and the caller resends it with the same key.
func TestRelaySessionLostMidCall(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	ch := relayAsync(h.m, context.Background())
	sentCall(t, c)
	start := time.Now()
	_ = c.Close()
	got := waitRelay(t, ch)
	if !errors.Is(got.err, ErrSessionLost) || got.r != nil {
		t.Fatal(got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("waited for the call timeout")
	}
	h.wait("down", func(s Status) bool { return !s.Up })
	if _, err := h.m.Relay(context.Background(), deviceCall()); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
}

// A result is matched to the session its call went out on.
func TestRelayResultFromAnotherSessionIgnored(t *testing.T) {
	h := newHarness(t)
	old := h.up(h.dial())
	old.in <- drainMsg(120000)
	nc := newConn(transport.TLS, h.clock)
	nc.info.SessionID = []byte("fedcba9876543210")
	h.dial().reply <- dialRes{conn: nc}
	nc.in <- routeSetMsg(t, 1, nc.info.SessionID)
	h.wait("switched", func(s Status) bool { return s.SessionID == "ZmVkY2JhOTg3NjU0MzIxMA" })
	ch := relayAsync(h.m, context.Background())
	call := sentCall(t, nc)
	noCall(t, old)
	old.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(), Class: pb.ResultClass_DONE, HttpStatus: 409}}}
	select {
	case got := <-ch:
		t.Fatal("result of the retired session taken:", got)
	case <-time.After(100 * time.Millisecond):
	}
	nc.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(), Class: pb.ResultClass_DONE, HttpStatus: 200}}}
	if got := waitRelay(t, ch); got.err != nil || got.r.GetHttpStatus() != 200 {
		t.Fatal(got)
	}
}

func TestRelayCancelledAndTimedOut(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	ctx, cancel := context.WithCancel(context.Background())
	ch := relayAsync(h.m, ctx)
	sentCall(t, c)
	cancel()
	if got := waitRelay(t, ch); !errors.Is(got.err, context.Canceled) {
		t.Fatal(got)
	}
	old := callTimeout
	callTimeout = 50 * time.Millisecond
	t.Cleanup(func() { callTimeout = old })
	ch = relayAsync(h.m, context.Background())
	call := sentCall(t, c)
	if got := waitRelay(t, ch); !errors.Is(got.err, errCallTimeout) {
		t.Fatal(got)
	}
	// A late result for a call that gave up is dropped.
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_DeviceResult{DeviceResult: &pb.DeviceResult{CallId: call.GetCallId(), Class: pb.ResultClass_DONE, HttpStatus: 200}}}
	h.settle()
	h.m.callMu.Lock()
	n := len(h.m.calls)
	h.m.callMu.Unlock()
	if n != 0 {
		t.Fatal(n, "calls left registered")
	}
}

func TestRelaySendFailure(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	l := h.m.relay.Load()
	_ = c.Close()
	if _, err := h.m.relayOn(context.Background(), l, deviceCall()); err == nil {
		t.Fatal("send on a closed session succeeded")
	}
	h.m.callMu.Lock()
	n := len(h.m.calls)
	h.m.callMu.Unlock()
	if n != 0 {
		t.Fatal(n, "calls left registered")
	}
}

// Stopping the tunnel (kill switch, hold, manager stop) leaves nothing to
// carry calls.
func TestRelayStopsWithTheManager(t *testing.T) {
	h := newHarness(t)
	h.up(h.dial())
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not stop")
	}
	h.done <- nil
	if _, err := h.m.Relay(context.Background(), deviceCall()); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
}
