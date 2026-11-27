package updatecheck

import (
	"testing"
	"time"
)

// A key-set entry listed without a sha256 hash cannot be matched, so the
// metadata is not fresh.
func TestListedKeySetWithoutHashIsNotFresh(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	if !c.saved.KeySetListed || !c.Fresh(t0) {
		t.Fatal("listed key set not recorded")
	}
	c.mu.Lock()
	c.saved.ListedKeySetSHA256, c.saved.KeySetSHA256 = "", ""
	c.mu.Unlock()
	if c.Fresh(t0) {
		t.Fatal("fresh with a listed key set that has no hash")
	}
}

// A verification time far ahead, from a clock that ran ahead, is dropped
// at the next check once it lies past the new timestamp's expiry.
func TestClockAheadRecovers(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	c.mu.Lock()
	c.saved.VerifiedAt = t0.Add(365 * 24 * time.Hour)
	c.mu.Unlock()
	if c.Fresh(t0) {
		t.Fatal("fresh before a future verification")
	}
	if !c.Status().ClockAhead {
		t.Fatal("clock ahead not shown")
	}
	mustCheck(t, c)
	if !c.Fresh(t0) {
		t.Fatal("not fresh after the check dropped the future verification time")
	}
	if !c.Status().ClockAhead {
		t.Fatal("dropped verification time not reported")
	}
	// A verification time within the timestamp's life is kept.
	f.setNow(t0.Add(time.Hour))
	mustCheck(t, c)
	f.setNow(t0)
	mustCheck(t, c)
	if v := c.Status().VerifiedAt; !v.Equal(t0.Add(time.Hour)) {
		t.Fatalf("verified at %v", v)
	}
}
