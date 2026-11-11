package caps

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
)

func TestEdgeBudgetMatchesAgent(t *testing.T) {
	if EdgeSessionBudget != AgentBudget || PreHelloBudget != 16<<20 {
		t.Fatal(EdgeSessionBudget, PreHelloBudget)
	}
}

// 100 connections that have not sent Hello share the pre-Hello pool, are
// refused beyond it, and never touch the global budget.
func TestPreHelloPool(t *testing.T) {
	pre := NewBudget(PreHelloBudget)
	global := NewBudget(EdgeBudget)
	var gates []*Gate
	refused := 0
	for i := 0; i < 100; i++ {
		g := NewEdgeGate(EdgeSessionBudget, DefaultAgentMaxStreams, pre)
		s, _ := g.NewSpan()
		if err := s.ReserveMemory(InitialWindow, 255); err != nil {
			if !errors.Is(err, ErrBudget) {
				t.Fatal(err)
			}
			refused++
			continue
		}
		gates = append(gates, g)
	}
	if len(gates) != PreHelloBudget/InitialWindow || refused != 100-len(gates) {
		t.Fatalf("%d admitted, %d refused", len(gates), refused)
	}
	if global.Used() != 0 || pre.Used() != PreHelloBudget {
		t.Fatal("pre-Hello charged the global budget", global.Used(), pre.Used())
	}
	if err := gates[0].Promote(global); err != nil {
		t.Fatal(err)
	}
	if global.Used() != InitialWindow || pre.Used() != PreHelloBudget-InitialWindow {
		t.Fatal("promote did not move the charge", global.Used(), pre.Used())
	}
	s, _ := gates[0].NewSpan()
	if err := s.ReserveMemory(InitialWindow, 255); err != nil || global.Used() != 2*InitialWindow || pre.Used() != PreHelloBudget-InitialWindow {
		t.Fatal("after promote", err, global.Used(), pre.Used())
	}
	s.Done()
	if global.Used() != InitialWindow {
		t.Fatal("release after promote", global.Used())
	}
	if err := gates[1].Promote(NewBudget(InitialWindow - 1)); !errors.Is(err, ErrBudget) {
		t.Fatal("promote past the global budget", err)
	}
	if pre.Used() != PreHelloBudget-InitialWindow {
		t.Fatal("failed promote moved the charge")
	}
	empty := NewEdgeGate(EdgeSessionBudget, DefaultAgentMaxStreams, pre)
	if err := empty.Promote(NewBudget(0)); err != nil {
		t.Fatal("promote with nothing held", err)
	}
	if err := gates[0].Promote(global); err == nil {
		t.Fatal("second promote")
	}
}

// With 128 data streams open on the edge, one busy download still grows
// its edge window past 6 MiB within the 48 MiB session budget.
func TestEdge128StreamsBusyGrows(t *testing.T) {
	edge := NewEdgeGate(EdgeSessionBudget, DefaultAgentMaxStreams, NewBudget(EdgeBudget))
	agent := NewAgentGate(AgentBudget, DefaultAgentMaxStreams)
	es, as := sessions(t, 10*time.Millisecond, edge, agent)
	go func() {
		for {
			s, err := as.AcceptStream()
			if err != nil {
				return
			}
			go func(s *yamux.Stream) {
				one := make([]byte, 1)
				if _, err := io.ReadFull(s, one); err != nil || one[0] != 1 {
					return
				}
				buf := make([]byte, 1<<20)
				for {
					if _, err := s.Write(buf); err != nil {
						return
					}
				}
			}(s)
		}
	}()
	var busy *yamux.Stream
	for i := 0; i < DefaultAgentMaxStreams; i++ {
		s, err := es.OpenStream(t.Context())
		if err != nil {
			t.Fatalf("stream %d: %v", i+1, err)
		}
		mark := byte(0)
		if i == 0 {
			busy, mark = s, 1
		}
		s.Write([]byte{mark})
	}
	go io.Copy(io.Discard, busy)
	deadline := time.Now().Add(20 * time.Second)
	for edge.PeakStream() <= 6<<20 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if edge.PeakStream() <= 6<<20 {
		t.Fatalf("busy stream reached only %d", edge.PeakStream())
	}
	if edge.Peak() > EdgeSessionBudget {
		t.Fatalf("edge reserved %d of %d", edge.Peak(), EdgeSessionBudget)
	}
}
