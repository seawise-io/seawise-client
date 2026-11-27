package transport

import (
	"errors"
	"testing"
	"time"
)

func TestDialRefusedWhileKeySetHeld(t *testing.T) {
	e := newEdge(t)
	reason := HoldKeySetMissing
	d := e.dialer(t, func(c *Config) { c.KeySetHold = func() string { return reason } })
	_, err := d.Dial(ctx(t), testName, TLS)
	var te *Error
	if !errors.Is(err, ErrKeySetHeld) || !errors.As(err, &te) || te.Kind != Local || te.Reason != HoldKeySetMissing {
		t.Fatalf("held: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	e.mu.Lock()
	accepts := e.accepts
	e.mu.Unlock()
	if accepts != 0 {
		t.Fatal("a held key set opened a connection")
	}
	reason = ""
	s, err := d.Dial(ctx(t), testName, TLS)
	if err != nil {
		t.Fatalf("released: %v", err)
	}
	_ = s.Close()
}
