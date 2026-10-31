package session

import (
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"

	"github.com/seawise/client/internal/transport"
)

func TestMissingKeySetHoldsDialsWithRedialTimer(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	r.reply <- dialRes{err: &transport.Error{Kind: transport.Local, Reason: transport.HoldKeySetMissing, Err: transport.ErrKeySetHeld}}
	at := h.clock.Now().Add(LocalRetry)
	s := h.wait("key set hold", func(s Status) bool { return s.LocalHold == transport.HoldKeySetMissing })
	if s.LocalHoldText != "waiting for signing keys" || !s.NextDial.Equal(at) || s.State != ladder.Own || s.Up {
		t.Fatalf("%+v", s)
	}
	h.advance(LocalRetry)
	h.up(h.dial())
	if s := h.wait("released", func(s Status) bool { return s.Up }); s.LocalHold != "" || s.LocalHoldText != "" {
		t.Fatalf("hold kept after a session came up: %+v", s)
	}
}

func TestOtherLocalRefusalsAreNotHolds(t *testing.T) {
	h := newHarness(t)
	r := h.dial()
	r.reply <- dialRes{err: &transport.Error{Kind: transport.Local, Reason: "edge_list"}}
	s := h.wait("local retry", func(s Status) bool { return !s.NextDial.IsZero() })
	if s.LocalHold != "" {
		t.Fatalf("%+v", s)
	}
	_ = time.Second
}
