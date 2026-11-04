package updatecheck

import (
	"testing"
	"time"
)

// A check with the clock moved back never moves the verification time back,
// so it cannot widen the freshness window.
func TestVerifiedAtNeverMovesBack(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	f.setNow(t0.Add(48 * time.Hour))
	mustCheck(t, c)
	f.setNow(t0.Add(time.Hour))
	mustCheck(t, c)
	if v := c.Status().VerifiedAt; v == nil || !v.Equal(t0.Add(48*time.Hour)) {
		t.Fatalf("verified at %v", v)
	}
	if c.Fresh(t0.Add(time.Hour)) {
		t.Fatal("fresh before the latest verification")
	}
}
