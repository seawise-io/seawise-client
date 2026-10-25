package caps

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
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

func TestYamuxConfig(t *testing.T) {
	c, err := YamuxConfig(InitialWindow, 128)
	if err != nil {
		t.Fatal(err)
	}
	if c.EnableKeepAlive || c.MaxStreamWindowSize != InitialWindow || c.AcceptBacklog != 128 ||
		c.StreamOpenTimeout != StreamOpenTimeout || c.StreamCloseTimeout != StreamCloseTimeout || c.LogOutput != io.Discard {
		t.Fatalf("%+v", c)
	}
	for _, bad := range [][2]uint32{{InitialWindow - 1, 1}, {InitialWindow, 0}, {InitialWindow, 4097}} {
		if _, err := YamuxConfig(bad[0], bad[1]); err != ErrConfig {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, err := YamuxConfig(InitialWindow, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := YamuxConfig(InitialWindow, 1); err != nil {
		t.Fatal(err)
	}
}

type countConn struct {
	net.Conn
	wrote atomic.Int64
}

func (c *countConn) Write(p []byte) (int, error) {
	c.wrote.Add(int64(len(p)))
	return c.Conn.Write(p)
}

func pair(t *testing.T, client, server *yamux.Config) (*yamux.Session, *yamux.Session, *countConn, *countConn) {
	t.Helper()
	a, b := net.Pipe()
	ca, cb := &countConn{Conn: a}, &countConn{Conn: b}
	cs, err := yamux.Client(ca, client)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := yamux.Server(cb, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs, ss, ca, cb
}

// bufferedBeforeBlock writes to a stream whose peer never reads and returns
// how many bytes the peer accepted before the writer blocked.
func bufferedBeforeBlock(t *testing.T, window uint32, total int) int {
	t.Helper()
	cfg, err := YamuxConfig(window, 8)
	if err != nil {
		t.Fatal(err)
	}
	cs, ss, _, _ := pair(t, cfg, cfg)
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		s, err := ss.AcceptStream()
		if err == nil {
			accepted <- s
		}
	}()
	st, err := cs.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	<-accepted
	st.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	n, _ := st.Write(make([]byte, total))
	return n
}

// The receive window is MaxStreamWindowSize from the first byte: yamux does
// not start at 256 KiB and grow on demand.
func TestYamuxWindowIsStatic(t *testing.T) {
	if n := bufferedBeforeBlock(t, InitialWindow, 1<<20); n != InitialWindow {
		t.Fatalf("256 KiB window buffered %d bytes", n)
	}
	if n := bufferedBeforeBlock(t, 6<<20, 6<<20); n != 6<<20 {
		t.Fatalf("6 MiB window buffered %d bytes before any read", n)
	}
}

func TestYamuxKeepaliveOff(t *testing.T) {
	cfg, err := YamuxConfig(InitialWindow, 8)
	if err != nil {
		t.Fatal(err)
	}
	cfg.KeepAliveInterval = 5 * time.Millisecond
	_, _, ca, cb := pair(t, cfg, cfg)
	time.Sleep(100 * time.Millisecond)
	if ca.wrote.Load() != 0 || cb.wrote.Load() != 0 {
		t.Fatalf("idle session sent %d and %d bytes", ca.wrote.Load(), cb.wrote.Load())
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

func TestAgentGate(t *testing.T) {
	g := NewStreamGate(AgentBudget, InitialWindow, nil)
	for i := 0; i < DefaultAgentMaxStreams; i++ {
		if !g.Admit() {
			t.Fatalf("stream %d refused", i+1)
		}
	}
	if g.Admit() || g.Open() != 128 {
		t.Fatal("stream 129 admitted")
	}
	g.Done()
	if g.Open() != 127 || !g.Admit() {
		t.Fatal("slot not reused")
	}
}

func TestEdgeGateShared(t *testing.T) {
	shared := NewBudget(3 * InitialWindow)
	g1 := NewStreamGate(2*InitialWindow, InitialWindow, shared)
	g2 := NewStreamGate(2*InitialWindow, InitialWindow, shared)
	if !g1.Admit() || !g1.Admit() || g1.Admit() {
		t.Fatal("session cap")
	}
	if !g2.Admit() || g2.Admit() {
		t.Fatal("shared cap")
	}
	if g2.Open() != 1 || shared.Used() != 3*InitialWindow {
		t.Fatal("refused stream kept its reservation")
	}
	g1.Done()
	if shared.Used() != 2*InitialWindow || !g2.Admit() {
		t.Fatal("shared release")
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
