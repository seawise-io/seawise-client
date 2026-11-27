package session

import (
	"sync"
	"testing"
	"time"
)

type wall struct {
	mu sync.Mutex
	t  time.Time
}

func (w *wall) now() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.t
}

func (w *wall) set(t time.Time) {
	w.mu.Lock()
	w.t = t
	w.mu.Unlock()
}

func TestSignedClockUsesSystemClockUntilSignedTime(t *testing.T) {
	w := &wall{t: time.Unix(1700000000, 0)}
	sc := NewSignedClock(w.now)
	if !sc.Now().Equal(w.now()) {
		t.Fatal(sc.Now())
	}
	if _, ok := sc.Floor(); ok {
		t.Fatal("floor before any signed time")
	}
}

func TestSignedClockCorrectsBothWays(t *testing.T) {
	for _, skew := range []time.Duration{-3 * time.Hour, 3 * time.Hour, 0} {
		w := &wall{t: time.Unix(1700000000, 0).Add(skew)}
		sc := NewSignedClock(w.now)
		sc.Observe(1700000000)
		if got := sc.Now().Unix(); got != 1700000000 {
			t.Fatalf("skew %s: %d", skew, got)
		}
		w.set(w.now().Add(90 * time.Second))
		if got := sc.Now().Unix(); got != 1700000090 {
			t.Fatalf("skew %s: elapsed not applied: %d", skew, got)
		}
	}
}

func TestSignedClockNeverBelowFloor(t *testing.T) {
	w := &wall{t: time.Unix(1700000000, 0)}
	sc := NewSignedClock(w.now)
	sc.Observe(1700000100)
	w.set(time.Unix(1600000000, 0))
	if got := sc.Now().Unix(); got < 1700000100 {
		t.Fatal("clock moved back below the signed floor:", got)
	}
	if f, ok := sc.Floor(); !ok || f != 1700000100 {
		t.Fatal(f, ok)
	}
}

func TestSignedClockIgnoresOlderSignedTime(t *testing.T) {
	// A system clock ahead, so older times are not closer to it.
	w := &wall{t: time.Unix(1700001000, 0)}
	sc := NewSignedClock(w.now)
	sc.Observe(1700000100)
	sc.Observe(1700000050) // older than the last
	sc.Observe(1699999000) // far behind both clocks
	if got := sc.Now().Unix(); got != 1700000100 {
		t.Fatal(got)
	}
	sc.Observe(1700000200)
	if got := sc.Now().Unix(); got != 1700000200 {
		t.Fatal(got)
	}
	sc.Observe(0)
	sc.Observe(-5)
	if got := sc.Now().Unix(); got != 1700000200 {
		t.Fatal(got)
	}
}

func TestSignedClockConcurrent(t *testing.T) {
	// Every signed time agrees with the system clock.
	sc := NewSignedClock(func() time.Time { return time.Unix(1700000200, 0) })
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 200 {
				sc.Observe(1700000000 + int64(i*30+j))
				_ = sc.Now()
			}
		}()
	}
	wg.Wait()
	if f, _ := sc.Floor(); f != 1700000409 {
		t.Fatal(f)
	}
}

func TestSignedClockEdges(t *testing.T) {
	w := &wall{t: time.Unix(1700000000, 0)}
	sc := NewSignedClock(w.now)
	sc.Observe(0)
	if _, ok := sc.Floor(); ok || !sc.Now().Equal(w.now()) {
		t.Fatal("zero signed time applied")
	}
	sc.Observe(1700000500)
	w.set(w.now().Add(60 * time.Second))
	sc.Observe(1700000500)
	if got := sc.Now().Unix(); got != 1700000560 {
		t.Fatal("a repeated signed time moved the clock back:", got)
	}
}
