package caps

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
)

func TestYamuxConfig(t *testing.T) {
	c, err := YamuxConfig(128)
	if err != nil {
		t.Fatal(err)
	}
	if c.EnableKeepAlive || c.InitialStreamWindowSize != InitialWindow || c.MaxStreamWindowSize != MaxWindow ||
		c.MaxIncomingStreams != 128 || c.AcceptBacklog != 128 || c.MeasureRTTInterval != MeasureRTTInterval || c.LogOutput != io.Discard {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []uint32{0, MaxStreamsLimit + 1} {
		if _, err := YamuxConfig(bad); err != ErrConfig {
			t.Errorf("%d: %v", bad, err)
		}
	}
	for _, ok := range []uint32{1, MaxStreamsLimit} {
		if _, err := YamuxConfig(ok); err != nil {
			t.Errorf("%d: %v", ok, err)
		}
	}
}

func TestAgentBudgetSplit(t *testing.T) {
	if AgentBudget != 48<<20 || DefaultAgentMaxStreams != 128 {
		t.Fatal("budget constants")
	}
	if g := AgentGrowth(AgentBudget, DefaultAgentMaxStreams); g != AgentBudget-129*InitialWindow || g < MaxWindow-InitialWindow {
		t.Fatal("growth pool", g)
	}
	if AgentGrowth(InitialWindow, 128) != 0 {
		t.Fatal("negative growth pool")
	}
}

func TestAgentGatePools(t *testing.T) {
	// One data stream: initial pool of 2 windows, growth pool of 2.
	g := NewAgentGate(4*InitialWindow, 1)
	var spans []yamux.MemoryManager
	for i := 0; i < 3; i++ {
		s, _ := g.NewSpan()
		if err := s.ReserveMemory(InitialWindow, 255); err != nil {
			t.Fatalf("initial window %d refused: %v", i+1, err)
		}
		spans = append(spans, s)
	}
	if err := spans[0].ReserveMemory(InitialWindow, 128); err != nil {
		t.Fatal("growth within the pool refused", err)
	}
	if err := spans[1].ReserveMemory(1, 128); !errors.Is(err, ErrBudget) {
		t.Fatal("growth past the pool granted", err)
	}
	extra, _ := g.NewSpan()
	if err := extra.ReserveMemory(InitialWindow, 255); !errors.Is(err, ErrBudget) {
		t.Fatal("initial window past both pools granted", err)
	}
	if g.Used() != 4*InitialWindow || g.Peak() != 4*InitialWindow || g.PeakStream() != 2*InitialWindow {
		t.Fatal(g.Used(), g.Peak(), g.PeakStream())
	}
	spans[0].ReleaseMemory(InitialWindow / 2)
	if err := spans[1].ReserveMemory(InitialWindow/2, 128); err != nil {
		t.Fatal("released growth not reusable", err)
	}
	spans[0].Done()
	spans[0].Done()
	if g.Used() != 2*InitialWindow+InitialWindow/2 {
		t.Fatal("done", g.Used())
	}
	if err := extra.ReserveMemory(InitialWindow, 255); err != nil {
		t.Fatal("initial window freed by done not reusable", err)
	}
	spans[1].ReleaseMemory(0)
	spans[1].ReleaseMemory(4 * InitialWindow)
	if g.Used() != 2*InitialWindow {
		t.Fatal("release past the span's reservation", g.Used())
	}
	small := NewAgentGate(InitialWindow/2, 1)
	s, _ := small.NewSpan()
	if err := s.ReserveMemory(InitialWindow, 255); !errors.Is(err, ErrBudget) {
		t.Fatal("budget below one window")
	}
}

func TestEdgeGateStrict(t *testing.T) {
	global := NewBudget(3 * InitialWindow)
	a := NewEdgeGate(2*InitialWindow, global)
	b := NewEdgeGate(2*InitialWindow, global)
	open := func(g *Gate) error {
		s, _ := g.NewSpan()
		return s.ReserveMemory(InitialWindow, 255)
	}
	if open(a) != nil || open(a) != nil || !errors.Is(open(a), ErrBudget) {
		t.Fatal("session cap")
	}
	if open(b) != nil || !errors.Is(open(b), ErrBudget) {
		t.Fatal("global cap")
	}
	if b.Used() != InitialWindow || global.Used() != 3*InitialWindow {
		t.Fatal("refused reservation kept", b.Used(), global.Used())
	}
	if err := (&span{g: a}).ReserveMemory(0, 128); err != nil {
		t.Fatal(err)
	}
}

// delayConn forwards bytes in both directions with a fixed one-way delay.
func delayPair(t *testing.T, oneWay time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var a2, b1 net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a2, _ = ln.Accept() }()
	a1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	var b2 net.Conn
	wg.Add(1)
	go func() { defer wg.Done(); b2, _ = ln2.Accept() }()
	b1, err = net.Dial("tcp", ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	go delayCopy(b1, a2, oneWay)
	go delayCopy(a2, b1, oneWay)
	t.Cleanup(func() { a1.Close(); a2.Close(); b1.Close(); b2.Close() })
	return a1, b2
}

type chunk struct {
	at   time.Time
	data []byte
}

func delayCopy(dst, src net.Conn, d time.Duration) {
	q := make(chan chunk, 1<<16)
	go func() {
		defer close(q)
		for {
			buf := make([]byte, 64<<10)
			n, err := src.Read(buf)
			if n > 0 {
				q <- chunk{time.Now().Add(d), buf[:n]}
			}
			if err != nil {
				return
			}
		}
	}()
	for c := range q {
		time.Sleep(time.Until(c.at))
		if _, err := dst.Write(c.data); err != nil {
			return
		}
	}
	dst.Close()
}

// sessions returns an edge (client) and agent (server) session over a link
// with the given one-way delay.
func sessions(t *testing.T, oneWay time.Duration, edge, agent *Gate) (*yamux.Session, *yamux.Session) {
	t.Helper()
	ec, ac := delayPair(t, oneWay)
	cfg, err := YamuxConfig(DefaultAgentMaxStreams)
	if err != nil {
		t.Fatal(err)
	}
	es, err := yamux.Client(ec, cfg, edge.NewSpan)
	if err != nil {
		t.Fatal(err)
	}
	as, err := yamux.Server(ac, cfg, agent.NewSpan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Close(); as.Close() })
	return es, as
}

// One busy stream grows its window past 6 MiB while idle streams keep
// their initial window and the session stays within its budget.
func TestBusyStreamGrowsIdleStreamsStaySmall(t *testing.T) {
	edge := NewEdgeGate(EdgeSessionBudget, NewBudget(EdgeBudget))
	agent := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
	es, as := sessions(t, 10*time.Millisecond, edge, agent)
	const idle = 40
	go func() {
		for {
			s, err := as.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, s)
		}
	}()
	for i := 0; i < idle; i++ {
		if _, err := es.OpenStream(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	busy, err := es.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 1<<20)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := busy.Write(buf); err != nil {
				return
			}
		}
	}()
	defer close(stop)
	deadline := time.Now().Add(20 * time.Second)
	for agent.PeakStream() <= 6<<20 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if agent.PeakStream() <= 6<<20 {
		t.Fatalf("busy stream window reached only %d bytes", agent.PeakStream())
	}
	if agent.Peak() > AgentBudget {
		t.Fatalf("session reserved %d bytes, budget %d", agent.Peak(), AgentBudget)
	}
	if n := agent.SmallSpans(InitialWindow); n < idle {
		t.Fatalf("only %d of %d idle streams kept the initial window", n, idle)
	}
}

// A single stream moves at least 50 MiB/s over a link with 100 ms RTT, in
// both directions: edge receiving (downloads) and agent receiving (uploads).
func TestThroughputAt100msRTT(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("throughput test needs a non-race, full run")
	}
	for _, upload := range []bool{false, true} {
		edge := NewEdgeGate(EdgeSessionBudget, NewBudget(EdgeBudget))
		agent := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
		es, as := sessions(t, 50*time.Millisecond, edge, agent)
		const total = 512 << 20
		recvGate := edge
		if upload {
			recvGate = agent
		}
		send := func(s *yamux.Stream) {
			buf := make([]byte, 1<<20)
			for sent := 0; sent < total; sent += len(buf) {
				if _, err := s.Write(buf); err != nil {
					return
				}
			}
			s.Close()
		}
		st, err := es.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		as2, err := as.AcceptStream()
		if err != nil {
			t.Fatal(err)
		}
		recv := st
		if upload {
			go send(st)
			recv = as2
			one := make([]byte, 1)
			if _, err := io.ReadFull(recv, one); err != nil {
				t.Fatal(err)
			}
		} else {
			go send(as2)
		}
		buf := make([]byte, 1<<20)
		got, warm := 0, 128<<20
		var start time.Time
		for got < total {
			n, err := recv.Read(buf)
			got += n
			if start.IsZero() && got >= warm {
				start = time.Now()
			}
			if err != nil {
				break
			}
		}
		if got != total {
			t.Fatalf("upload=%v: received %d of %d bytes", upload, got, total)
		}
		rate := float64(total-warm) / time.Since(start).Seconds() / (1 << 20)
		t.Logf("upload=%v: steady-state %.1f MiB/s, receive window peak %d", upload, rate, recvGate.PeakStream())
		if rate < 50 {
			t.Fatalf("upload=%v: %.1f MiB/s at 100 ms RTT, want at least 50", upload, rate)
		}
	}
}

func TestSmallSpans(t *testing.T) {
	g := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
	g.NewSpan()
	a, _ := g.NewSpan()
	a.ReserveMemory(InitialWindow, 255)
	b, _ := g.NewSpan()
	b.ReserveMemory(InitialWindow+1, 255)
	if n := g.SmallSpans(InitialWindow); n != 1 {
		t.Fatalf("%d small spans", n)
	}
}

// 128 data streams opened at once, all receiving, plus the agent's own
// stream 0 and a refused 129th stream, stay within the 48 MiB budget.
func Test128StreamsStayWithinBudget(t *testing.T) {
	edge := NewEdgeGate(EdgeSessionBudget, NewBudget(EdgeBudget))
	agent := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
	es, as := sessions(t, 5*time.Millisecond, edge, agent)
	go func() {
		for {
			s, err := as.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, s)
		}
	}()
	if _, err := as.OpenStream(t.Context()); err != nil {
		t.Fatal("stream 0", err)
	}
	var streams []*yamux.Stream
	for i := 0; i < DefaultAgentMaxStreams+1; i++ {
		s, err := es.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		streams = append(streams, s)
	}
	stop := make(chan struct{})
	defer close(stop)
	for _, s := range streams {
		go func(s *yamux.Stream) {
			buf := make([]byte, 256<<10)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := s.Write(buf); err != nil {
					return
				}
			}
		}(s)
	}
	time.Sleep(3 * time.Second)
	if agent.Peak() > AgentBudget {
		t.Fatalf("agent reserved %d bytes, budget %d", agent.Peak(), AgentBudget)
	}
	if agent.PeakStream() <= InitialWindow {
		t.Fatal("no stream grew")
	}
	t.Logf("peak %d of %d, largest stream %d", agent.Peak(), AgentBudget, agent.PeakStream())
}
