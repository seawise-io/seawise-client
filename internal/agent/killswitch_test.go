package agent

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

func TestKillSwitchDropsEverything(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), "run", nil)
	eventually(t, "frpc ready", func() bool { return len(h.status().Proxies) == 1 })
	port := confValue(t, h.agent.ConfigPath(), "localPort")
	if err := h.agent.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	s := h.status()
	if s.Running || !s.Paused || len(s.Holds) != 1 || s.Holds[0] != HoldKillSwitch || h.count("exit") != 1 {
		t.Fatalf("status after kill switch: %+v %v", s, h.events())
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second); err == nil {
		c.Close()
		t.Fatal("forwarder still listening")
	}
	if _, err := os.Stat(h.agent.ConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("frpc config left on disk: %v", err)
	}
	if !h.st.State().HasHold(store.HoldKillSwitch) {
		t.Fatal("kill switch not persisted")
	}
	if err := h.agent.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); s.Running {
		t.Fatal("resume released the kill switch")
	}
	if err := h.agent.SetKillSwitch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if s := h.status(); !s.Running || s.Paused || h.st.State().HasHold(store.HoldKillSwitch) {
		t.Fatalf("restore: %+v", s)
	}
}

func TestKillSwitchSurvivesRestart(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	if err := st.Update(func(s *store.State) error { s.Holds = []string{store.HoldKillSwitch}; return nil }); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if s := h.status(); s.Running || !s.Paused || h.count("start") != 0 {
		t.Fatalf("started with a persisted kill switch: %+v", s)
	}
	if err := h.agent.SetKillSwitch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	eventually(t, "frpc ready", func() bool { return h.status().Running })
}

func TestServerPublicRefusedWithoutLocalToggle(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	on, off := true, false
	err := st.Update(func(s *store.State) error {
		s.Targets = append(s.Targets,
			store.Target{LocalID: "p1", Name: "srvpublic", Host: "192.168.1.40", Port: 80, Subdomain: "p1", Source: store.SourceLocal, ConfirmedAt: &confirmed, ServerPublic: true},
			store.Target{LocalID: "p2", Name: "localprivate", Host: "192.168.1.41", Port: 80, Subdomain: "p2", Source: store.SourceLocal, ConfirmedAt: &confirmed, ServerPublic: true, Public: &off},
			store.Target{LocalID: "p3", Name: "bothpublic", Host: "192.168.1.42", Port: 80, Subdomain: "p3", Source: store.SourceLocal, ConfirmedAt: &confirmed, ServerPublic: true, Public: &on},
			store.Target{LocalID: "p4", Name: "localonly", Host: "192.168.1.43", Port: 80, Subdomain: "p4", Source: store.SourceLocal, ConfirmedAt: &confirmed, Public: &on},
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, st, "run", nil)
	eventually(t, "frpc ready", func() bool { return h.status().Running })
	b, _ := os.ReadFile(h.agent.ConfigPath())
	conf := string(b)
	for _, bad := range []string{"srvpublic", "localprivate"} {
		if strings.Contains(conf, bad) {
			t.Errorf("%s rendered against the local toggle:\n%s", bad, conf)
		}
	}
	for _, good := range []string{"bothpublic", "localonly", "jellyfin"} {
		if !strings.Contains(conf, good) {
			t.Errorf("%s missing:\n%s", good, conf)
		}
	}
	refused := map[string]string{}
	for _, r := range h.status().Refused {
		refused[r.LocalID] = r.Reason
	}
	if !strings.Contains(refused["p1"], "private on this machine") || !strings.Contains(refused["p2"], "private on this machine") {
		t.Fatalf("refusals = %v", refused)
	}
}
