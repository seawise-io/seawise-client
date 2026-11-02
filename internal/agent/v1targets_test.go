package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

var managementPorts = []int{2375, 2376, 2377, 2379, 2380, 6443, 10250, 10255}

func TestV1TargetsAdmitted(t *testing.T) {
	no := false
	gw := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	var targets []store.Target
	want := map[string]bool{}
	add := func(id string, tg store.Target, ok bool) {
		tg.LocalID, tg.Subdomain = id, "s-"+id
		targets = append(targets, tg)
		want[id] = ok
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1", "192.168.1.20", "10.0.0.5", "93.184.216.34", "nas.lan"} {
		for _, p := range managementPorts {
			add(fmt.Sprintf("v1-%s-%d", host, p), store.Target{Host: host, Port: p, Source: store.SourceV1Machine, Grandfathered: true}, true)
			add(fmt.Sprintf("new-%s-%d", host, p), store.Target{Host: host, Port: p, Source: store.SourceLocal}, true)
		}
	}
	add("gateway", store.Target{Host: "192.168.1.1", Port: 80, Source: store.SourceLocal}, true)
	add("smtp", store.Target{Host: "93.184.216.34", Port: 25, Source: store.SourceLocal}, true)
	add("frpc", store.Target{Host: "172.17.0.1", Port: 8096, Source: store.SourceV1FRPC, Grandfathered: true}, true)
	add("server-public", store.Target{Host: "192.168.1.30", Port: 80, Source: store.SourceLocal, ServerPublic: true, Public: &no}, true)
	add("meta", store.Target{Host: "169.254.169.254", Port: 80, Source: store.SourceLocal}, false)
	add("meta-v1", store.Target{Host: "169.254.169.254", Port: 80, Source: store.SourceV1Machine, Grandfathered: true}, false)
	add("azure", store.Target{Host: "168.63.129.16", Port: 80, Source: store.SourceLocal}, false)
	add("aws6", store.Target{Host: "[fd00:ec2::254]", Port: 80, Source: store.SourceLocal}, false)
	add("ll4", store.Target{Host: "169.254.10.10", Port: 80, Source: store.SourceLocal}, false)
	add("ll6", store.Target{Host: "fe80::1", Port: 80, Source: store.SourceLocal}, false)
	add("nat64-meta", store.Target{Host: "64:ff9b::a9fe:a9fe", Port: 80, Source: store.SourceLocal}, false)

	ok, refused := admit(targets, gw)
	got := map[string]bool{}
	for _, tg := range ok {
		got[tg.LocalID] = true
	}
	for _, r := range refused {
		if got[r.LocalID] || r.Reason == "" {
			t.Errorf("%s: admitted and refused, or no reason: %q", r.LocalID, r.Reason)
		}
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: admitted=%v want %v", id, got[id], w)
		}
	}
	if len(ok)+len(refused) != len(targets) {
		t.Fatalf("admitted %d refused %d of %d", len(ok), len(refused), len(targets))
	}
}

func echoOnce(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err == nil {
					_, _ = io.WriteString(c, "echo:"+line)
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func forwards(t *testing.T, port int) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "hi\n"); err != nil {
		return false
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && line == "echo:hi\n"
}

// A new app is forwarded as soon as it is stored, with no local step.
func TestNewAppForwardedWithoutConfirmation(t *testing.T) {
	st := pairedStore(t, t.TempDir())
	h := newHarness(t, st, nil)
	h.status()
	backend := echoOnce(t)
	no := false
	err := st.Update(func(s *store.State) error {
		s.Targets = append(s.Targets,
			store.Target{LocalID: "n", Name: "new", Host: "127.0.0.1", Port: backend, Subdomain: "n1", Source: store.SourceLocal},
			store.Target{LocalID: "p", Name: "pub", Host: "localhost", Port: backend, Subdomain: "p1", Source: store.SourceV1Machine,
				Grandfathered: true, ServerPublic: true, Public: &no})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.agent.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := h.status()
	ports := h.agent.fwdPorts()
	for _, id := range []string{"n", "p"} {
		if ports[id] == 0 || !forwards(t, ports[id]) {
			t.Fatalf("%s not forwarded: ports %v refused %v", id, ports, s.Refused)
		}
	}
	if len(s.Refused) != 1 || s.Refused[0].LocalID != "m" {
		t.Fatalf("refused %v", s.Refused)
	}
	if _, ok := ports["m"]; ok {
		t.Fatal("metadata app has a forwarder")
	}
}
