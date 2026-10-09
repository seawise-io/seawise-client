package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

func listening(port string) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestKillSwitchTakesEffectWhenRequestIsCancelled(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	h := newHarness(t, st, "stubborn", nil)
	eventually(t, "frpc ready", func() bool { return len(h.status().Proxies) == 1 })

	// Keep the loop busy restarting a frpc that ignores SIGTERM.
	if err := st.Update(func(s *store.State) error { s.Account.FRPServerPort = 7001; return nil }); err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.agent.Reconcile(context.Background()) }()
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = h.agent.SetKillSwitch(ctx, true)
	if !st.State().HasHold(store.HoldKillSwitch) {
		t.Fatal("kill switch not persisted")
	}
	eventually(t, "tunnels down", func() bool {
		s := h.status()
		return !s.Running && s.Paused && len(s.Holds) == 1 && s.Holds[0] == HoldKillSwitch
	})
	time.Sleep(300 * time.Millisecond)
	if s := h.status(); s.Running {
		t.Fatalf("frpc running with the kill switch on: %+v", s)
	}
}

func TestKillSwitchClosesForwarderBeforeStoppingFRPC(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "stubborn", nil)
	eventually(t, "frpc ready", func() bool { return len(h.status().Proxies) == 1 })
	port := confValue(t, h.agent.ConfigPath(), "localPort")
	if !listening(port) {
		t.Fatal("forwarder not listening")
	}
	start := time.Now()
	done := make(chan struct{})
	go func() { _ = h.agent.SetKillSwitch(context.Background(), true); close(done) }()
	for listening(port) {
		if time.Since(start) > time.Second {
			t.Fatal("forwarder still open while frpc is being stopped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("expected frpc stop to take the stop timeout")
	default:
	}
	<-done
}

func TestReleaseCannotClearKillSwitch(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	h := newHarness(t, st, "run", nil)
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if err := h.agent.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Release(context.Background(), HoldKillSwitch); err == nil {
		t.Fatal("Release accepted the kill switch reason")
	}
	if err := h.agent.Hold(context.Background(), HoldKillSwitch); err == nil {
		t.Fatal("Hold accepted the kill switch reason")
	}
	if s := h.status(); s.Running || !st.State().HasHold(store.HoldKillSwitch) {
		t.Fatalf("kill switch cleared: %+v", s)
	}
}

func TestPersistedKillSwitchAppliedWithoutIntent(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	h := newHarness(t, st, "run", nil)
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	if err := st.Update(func(s *store.State) error { s.Holds = []string{store.HoldKillSwitch}; return nil }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "tunnels down", func() bool { return !h.status().Running })
}
