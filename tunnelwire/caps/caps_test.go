package caps

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestDerivedStreams(t *testing.T) {
	if DefaultAgentMaxStreams != 128 {
		t.Fatal(DefaultAgentMaxStreams)
	}
	cases := []struct {
		budget int64
		window uint32
		want   uint32
	}{
		{AgentBudget, InitialWindow, 128},
		{AgentBudget, 6 << 20, 5},
		{AgentBudget - 1, InitialWindow, 127},
		{InitialWindow, InitialWindow, 1},
		{InitialWindow - 1, InitialWindow, 0},
		{0, InitialWindow, 0},
		{-1, InitialWindow, 0},
		{AgentBudget, 0, 0},
		{1 << 40, InitialWindow, 4096},
		{4096 * InitialWindow, InitialWindow, 4096},
		{4097 * InitialWindow, InitialWindow, 4096},
		{4095 * InitialWindow, InitialWindow, 4095},
	}
	for _, c := range cases {
		if got := MaxStreams(c.budget, c.window); got != c.want {
			t.Errorf("MaxStreams(%d, %d) = %d, want %d", c.budget, c.window, got, c.want)
		}
	}
	if SessionStreams(128, 64, 1024) != 64 || SessionStreams(128, 4096, 3) != 3 || SessionStreams(100, 200, 300) != 100 {
		t.Fatal("SessionStreams")
	}
}

func TestBudget(t *testing.T) {
	b := NewBudget(10)
	if !b.TryAcquire(4) || !b.TryAcquire(6) || b.TryAcquire(1) || b.Used() != 10 {
		t.Fatal("acquire")
	}
	if b.TryAcquire(0) || b.TryAcquire(-1) {
		t.Fatal("non-positive acquire")
	}
	b.Release(6)
	if b.Used() != 4 || !b.TryAcquire(6) {
		t.Fatal("release")
	}
	for _, n := range []int64{11, 0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("release %d did not panic", n)
				}
			}()
			b.Release(n)
		}()
	}
	b.Release(10)
	if b.Used() != 0 {
		t.Fatal(b.Used())
	}
}

func TestLiveness(t *testing.T) {
	t0 := time.Unix(1000, 0)
	l := NewLiveness(PingInterval, PingTimeout, t0)
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	step := func(s float64, wantPing, wantDead bool) {
		t.Helper()
		p, d := l.Check(at(s))
		if p != wantPing || d != wantDead {
			t.Fatalf("t=%v: ping %v dead %v", s, p, d)
		}
	}
	step(19.9, false, false)
	step(20, true, false)
	step(21, false, false)
	step(34.9, false, false)
	step(35, false, true)
	l.Received(at(36))
	if l.Silence(at(40)) != 4*time.Second {
		t.Fatal("silence")
	}
	step(55.9, false, false)
	step(56, true, false)
	l.Received(at(60))
	step(79, false, false)
	step(80, true, false)
	l.Received(at(10))
	if l.Silence(at(80)) != 20*time.Second {
		t.Fatal("received went backwards")
	}
}

func TestLivenessTrafficWithoutPong(t *testing.T) {
	t0 := time.Unix(0, 0)
	l := NewLiveness(PingInterval, PingTimeout, t0)
	for s := 0; s <= 600; s += 5 {
		now := t0.Add(time.Duration(s) * time.Second)
		l.Received(now)
		if _, dead := l.Check(now.Add(4 * time.Second)); dead {
			t.Fatal("session with traffic declared dead")
		}
	}
}

func TestLivenessConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	t0 := time.Unix(0, 0)
	l := NewLiveness(PingInterval, PingTimeout, t0)
	now := t0.Add(30 * time.Second)
	c := &LivenessConn{Conn: a, L: l, Now: func() time.Time { return now }}
	go b.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	if l.Silence(now) != 0 {
		t.Fatal("read did not count")
	}
	b.Close()
	now = now.Add(time.Second)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected EOF")
	}
	if l.Silence(now) != time.Second {
		t.Fatal("empty read counted")
	}
}

func TestSessionLifetime(t *testing.T) {
	if SessionLifetime(func(n int64) int64 { return 0 }) != 12*time.Hour {
		t.Fatal("low")
	}
	if SessionLifetime(func(n int64) int64 { return n - 1 }) != 24*time.Hour {
		t.Fatal("high")
	}
	var seen int64
	SessionLifetime(func(n int64) int64 { seen = n; return 0 })
	if seen != 43201 {
		t.Fatal(seen)
	}
	for range 100 {
		d := SessionLifetime(nil)
		if d < 12*time.Hour || d > 24*time.Hour || d%time.Second != 0 {
			t.Fatal(d)
		}
	}
}

var _ = bytes.MinRead
