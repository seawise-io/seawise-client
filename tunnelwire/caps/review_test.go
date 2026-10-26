package caps

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
)

func waitZero(t *testing.T, what string, f func() int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for f() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := f(); n != 0 {
		t.Fatalf("%s still holds %d bytes", what, n)
	}
}

// Parallel downloads that end by FIN, RST or Close release every byte on
// the session and the global budget, even when window growth races the
// stream's cleanup.
func TestDownloadsReleaseEverything(t *testing.T) {
	for round := 0; round < 5; round++ {
		global := NewBudget(EdgeBudget)
		edge := NewEdgeGate(EdgeSessionBudget, global)
		agent := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
		es, as := sessions(t, 2*time.Millisecond, edge, agent)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				st, err := es.OpenStream(t.Context())
				if err != nil {
					return
				}
				st.Write([]byte{byte(i)})
				buf := make([]byte, 256<<10)
				got := 0
				for got < 8<<20 {
					n, err := st.Read(buf)
					got += n
					if err != nil {
						return
					}
				}
				switch i % 3 {
				case 0:
					st.Close()
				case 1:
					st.Reset()
				default:
					st.CloseRead()
					st.CloseWrite()
				}
			}(i)
		}
		go func() {
			for {
				s, err := as.AcceptStream()
				if err != nil {
					return
				}
				go func(s *yamux.Stream) {
					one := make([]byte, 1)
					io.ReadFull(s, one)
					buf := make([]byte, 1<<20)
					for {
						if _, err := s.Write(buf); err != nil {
							s.Close()
							return
						}
					}
				}(s)
			}
		}()
		wg.Wait()
		as.Close()
		es.Close()
		waitZero(t, "edge session", edge.Used)
		waitZero(t, "global budget", global.Used)
		edge.mu.Lock()
		n := len(edge.spans)
		edge.mu.Unlock()
		if n != 0 {
			t.Fatalf("%d spans left", n)
		}
	}
}

func TestReserveAfterDoneRefused(t *testing.T) {
	global := NewBudget(EdgeBudget)
	g := NewEdgeGate(EdgeSessionBudget, global)
	s, _ := g.NewSpan()
	if err := s.ReserveMemory(InitialWindow, 255); err != nil {
		t.Fatal(err)
	}
	s.Done()
	if err := s.ReserveMemory(InitialWindow, 128); !errors.Is(err, ErrBudget) {
		t.Fatal("reservation after Done granted", err)
	}
	if g.Used() != 0 || global.Used() != 0 {
		t.Fatal("reservation after Done leaked", g.Used(), global.Used())
	}
	a := NewAgentGate(AgentBudget, 1)
	s, _ = a.NewSpan()
	s.Done()
	for _, prio := range []uint8{255, 128} {
		if err := s.ReserveMemory(InitialWindow, prio); !errors.Is(err, ErrBudget) {
			t.Fatal("agent reservation after Done granted", err)
		}
	}
	if a.Used() != 0 || a.initial.Used() != 0 || a.growth.Used() != 0 {
		t.Fatal("agent reservation after Done leaked")
	}
}

// Before Hello the agent can make the edge hold at most one stream window.
func TestPreHelloClientHoldsOneWindow(t *testing.T) {
	global := NewBudget(EdgeBudget)
	edge := NewEdgeGate(EdgeSessionBudget, global)
	agent := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
	_, as := sessions(t, time.Millisecond, edge, agent)
	for i := 0; i < 50; i++ {
		as.OpenStream(t.Context())
	}
	time.Sleep(300 * time.Millisecond)
	if edge.Used() > InitialWindow {
		t.Fatalf("edge holds %d bytes for agent-opened streams", edge.Used())
	}
	if edge.Peak() > 2*InitialWindow {
		t.Fatalf("edge peaked at %d bytes", edge.Peak())
	}
}

func TestEdgeYamuxConfig(t *testing.T) {
	c := EdgeYamuxConfig()
	if c.MaxIncomingStreams != 1 || c.AcceptBacklog != 1 || c.EnableKeepAlive || c.MaxStreamWindowSize != MaxWindow || yamux.VerifyConfig(c) != nil {
		t.Fatalf("%+v", c)
	}
}

func TestEdgeSessionBudgetMatchesSpec(t *testing.T) {
	if EdgeSessionBudget != 32<<20 {
		t.Fatal(EdgeSessionBudget)
	}
}

func TestRefusedOpensLeaveNoSpans(t *testing.T) {
	g := NewEdgeGate(InitialWindow, NewBudget(EdgeBudget))
	keep, _ := g.NewSpan()
	if err := keep.ReserveMemory(InitialWindow, 255); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		s, _ := g.NewSpan()
		if err := s.ReserveMemory(InitialWindow, 255); !errors.Is(err, ErrBudget) {
			t.Fatal("open past the budget granted")
		}
	}
	g.mu.Lock()
	n := len(g.spans)
	g.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d spans tracked, want 1", n)
	}
	a := NewAgentGate(InitialWindow, 0)
	s, _ := a.NewSpan()
	if err := s.ReserveMemory(2*InitialWindow, 255); !errors.Is(err, ErrBudget) {
		t.Fatal("agent open past both pools granted")
	}
	if len(a.spans) != 0 {
		t.Fatal("agent kept a refused span")
	}
}

// With the growth pool spent, every one of the 129 initial windows (128
// data streams and stream 0) still comes from the initial pool.
func TestStream129OpensWithGrowthPoolFull(t *testing.T) {
	g := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
	hog, _ := g.NewSpan()
	if err := hog.ReserveMemory(InitialWindow, 255); err != nil {
		t.Fatal(err)
	}
	if err := hog.ReserveMemory(int(AgentGrowth(AgentBudget, DefaultAgentMaxStreams)), 128); err != nil {
		t.Fatal("filling the growth pool", err)
	}
	if err := hog.ReserveMemory(1, 128); !errors.Is(err, ErrBudget) {
		t.Fatal("growth pool not full")
	}
	for i := 1; i < DefaultAgentMaxStreams+1; i++ {
		s, _ := g.NewSpan()
		if err := s.ReserveMemory(InitialWindow, 255); err != nil {
			t.Fatalf("stream %d refused with the growth pool full: %v", i+1, err)
		}
	}
	if g.Used() != AgentBudget {
		t.Fatal(g.Used(), AgentBudget)
	}
	extra, _ := g.NewSpan()
	if err := extra.ReserveMemory(InitialWindow, 255); !errors.Is(err, ErrBudget) {
		t.Fatal("window past the budget granted")
	}
}

func TestOutboundStreams(t *testing.T) {
	c := NewOutbound(2)
	if !c.TryOpen() || !c.TryOpen() || c.TryOpen() || c.Open() != 2 {
		t.Fatal("cap")
	}
	c.Done()
	if c.Open() != 1 || !c.TryOpen() {
		t.Fatal("release")
	}
	c.Done()
	c.Done()
	defer func() {
		if recover() == nil {
			t.Fatal("done without open did not panic")
		}
	}()
	c.Done()
}
