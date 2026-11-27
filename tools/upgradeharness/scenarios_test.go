//go:build upgradeharness

package upgradeharness

import (
	"strings"
	"testing"
	"time"
)

func since(t0 time.Time, f func(rec) bool) func(rec) bool {
	return func(r rec) bool { return !r.At.Before(t0) && f(r) }
}

func path(method, p string, status int) func(rec) bool {
	return func(r rec) bool {
		return r.Agent && r.Method == method && r.Path == p && (status == 0 || r.Status == status)
	}
}

// scenarioU: a 1.0.12 install upgraded while the device API is not live
// yet, stopped, then enrolled with a crash between enrolment and the
// switch, and restarted after the switch.
func (h *harness) scenarioU(t *testing.T) {
	h.s.reset()
	vol := h.v1Install(t, imageE, "u", false)
	sp := "/api/servers/" + h.s.serverID
	if h.count(func(r rec) bool { return !r.Agent && r.Path == sp+"/offline" }) != 1 {
		t.Error("1.0.12 did not send offline on a clean stop")
	}
	s0 := h.probe(t, vol)
	t.Logf("1.0.12 stopped volume: %d files\n%s", len(s0.Files), strings.Join(s0.Files, "\n"))
	if s0.has("frpc.toml") {
		t.Error("1.0.12 left frpc.toml on a clean stop")
	}
	agent := h.name("u-agent")

	// Step 2: enrol route not live.
	h.s.setPhase("u:pending")
	t2 := time.Now()
	h.startContainer(t, agent, h.clientSpec(h.agent, vol))
	waitFor(t, 2*time.Minute, "agent 1.x heartbeat", func() bool { return h.seen(since(t2, path("POST", sp+"/heartbeat", 200))) })
	waitFor(t, 2*time.Minute, "agent enrol attempt", func() bool { return h.seen(since(t2, path("POST", "/device/v2/enroll", 404))) })
	if r := h.s.records(); !hasToken(r, t2, sp+"/heartbeat", h.s.token) {
		t.Error("agent heartbeat without the 1.x token")
	}
	st := agentStatus(t, agent)
	if got := str(field(st, "enrolment", "state")); got != "enrolling" {
		t.Errorf("enrolment state %q, want enrolling", got)
	}
	h.s.setPhase("u:pending-stop")
	t2s := time.Now()
	h.stopContainer(t, agent, false)
	if n := h.count(since(t2s, path("POST", sp+"/offline", 200))); n != 1 {
		t.Errorf("agent sent offline %d times on a clean stop before enrolment, want 1", n)
	}
	if n := h.count(since(t2, func(r rec) bool {
		return r.Agent && strings.HasPrefix(r.Path, "/device/") && r.Path != "/device/v2/enroll"
	})); n != 0 {
		t.Errorf("%d device calls before enrolment", n)
	}
	s2 := h.probe(t, vol)
	sameFiles(t, "pending", s0, s2)
	ownerOnly(t, s2)
	key := enrolKey(s2)
	if enrolPhase(s2) != "pending" || key == "" {
		t.Fatalf("enrolment %q key %q, want pending with a key", enrolPhase(s2), key)
	}
	if s2.TokenLen != 64 {
		t.Errorf("token length %d in secrets.json before the switch", s2.TokenLen)
	}

	// Step 3: enrol live, confirm unavailable, 1.x API failing with 503
	// (retries must not outlive enrolment), crash while enrolled.
	h.s.set(func(s *standin) { s.confirmBlock, s.v1Down = true, true })
	h.s.setPhase("u:enrol")
	t3 := time.Now()
	h.startContainer(t, agent, h.clientSpec(h.agent, vol))
	waitFor(t, 2*time.Minute, "1.x call answered 503", func() bool { return h.seen(since(t3, path("POST", sp+"/heartbeat", 503))) })
	h.s.set(func(s *standin) { s.enrolOn = true })
	waitFor(t, 2*time.Minute, "enrolment", func() bool { return h.seen(since(t3, path("POST", "/device/v2/enroll", 200))) })
	enrolled := firstAt(h.s.records(), since(t3, path("POST", "/device/v2/enroll", 200)))
	waitFor(t, 2*time.Minute, "confirm attempt", func() bool { return h.seen(since(t3, path("POST", "/device/v2/enroll/confirm", 503))) })
	for _, r := range h.s.records() {
		if r.At.After(t3) && r.Agent && r.KeyID != "" && r.KeyID != key {
			t.Fatalf("agent used key %s, want the key made before enrolment %s", r.KeyID, key)
		}
	}
	h.s.setPhase("u:crash")
	h.stopContainer(t, agent, true)
	s3 := h.probe(t, vol)
	if enrolPhase(s3) != "enrolled" || enrolKey(s3) != key {
		t.Fatalf("after the crash: enrolment %q key %q", enrolPhase(s3), enrolKey(s3))
	}
	sameFiles(t, "enrolled", s0, s3)

	// Resume after the crash.
	h.s.set(func(s *standin) { s.confirmBlock, s.v1Down = false, false })
	h.s.setPhase("u:resume")
	t4 := time.Now()
	h.startContainer(t, agent, h.clientSpec(h.agent, vol))
	waitFor(t, 3*time.Minute, "switch", func() bool { return h.seen(since(t4, path("POST", "/device/v2/enroll/confirm", 200))) })
	if n := h.count(since(t4, path("POST", "/device/v2/enroll", 0))); n != 0 {
		t.Errorf("%d enrol calls after the crash, want none", n)
	}
	if !h.seen(since(t4, path("GET", "/device/v2/identity", 200))) {
		t.Error("no identity probe before the switch")
	}
	waitFor(t, 3*time.Minute, "adoption of the 1.x app", func() bool {
		h.s.mu.Lock()
		defer h.s.mu.Unlock()
		return len(h.s.apps) == 1 && h.s.apps[0].LocalID != ""
	})
	waitFor(t, time.Minute, "app sync adopted", func() bool {
		return field(agentStatus(t, agent), "app_sync", "adopted") == true
	})
	st = agentStatus(t, agent)
	if got := str(field(st, "enrolment", "state")); got != "switched" {
		t.Errorf("enrolment state %q, want switched", got)
	}
	h.s.setPhase("u:switched-stop")
	t5 := time.Now()
	h.stopContainer(t, agent, false)
	if n := h.count(since(t5, path("POST", sp+"/offline", 0))); n != 0 {
		t.Error("offline sent with the retired 1.x token")
	}
	s5 := h.probe(t, vol)
	sameFiles(t, "switched", s0, s5)
	ownerOnly(t, s5)
	if enrolPhase(s5) != "switched" || enrolKey(s5) != key {
		t.Errorf("enrolment %q key %q, want switched with %s", enrolPhase(s5), enrolKey(s5), key)
	}
	if s5.TokenLen != 0 {
		t.Error("the 1.x token is still in secrets.json after the switch")
	}
	h.s.mu.Lock()
	app := *h.s.apps[0]
	h.s.mu.Unlock()
	if ts := targets(s5); len(ts) != 1 || str(ts[0]["local_id"]) != app.LocalID || str(ts[0]["server_service_id"]) != app.ID {
		t.Errorf("targets %v, want the 1.x app linked to %s", ts, app.ID)
	}

	// Restart after the switch.
	h.s.setPhase("u:restart")
	t6 := time.Now()
	h.startContainer(t, agent, h.clientSpec(h.agent, vol))
	st = agentStatus(t, agent)
	if got := str(field(st, "enrolment", "state")); got != "switched" {
		t.Errorf("after restart enrolment state %q, want switched", got)
	}
	waitFor(t, 2*time.Minute, "app list after restart", func() bool { return h.seen(since(t6, path("GET", "/device/v2/apps", 200))) })
	h.stopContainer(t, agent, false)
	if n := h.count(since(t6, func(r rec) bool {
		return r.Agent && (strings.HasPrefix(r.Path, "/device/v2/enroll") || r.Path == "/device/v2/identity")
	})); n != 0 {
		t.Errorf("%d enrolment calls after the switch", n)
	}
	sameFiles(t, "restart", s0, h.probe(t, vol))

	h.noV1AfterEnrolment(t, enrolled)
	for _, p := range []string{"u:pending", "u:pending-stop", "u:enrol", "u:crash", "u:resume", "u:switched-stop", "u:restart"} {
		if n := h.s.frpsConns(p); n != 0 {
			t.Errorf("%d connections to the 1.x frps address in %s", n, p)
		}
	}
	h.noFailures(t)
}

// scenarioA: a 1.0.0 install stopped cleanly (or killed) and upgraded.
func (h *harness) scenarioA(t *testing.T, label string, kill bool) {
	h.s.reset()
	h.s.set(func(s *standin) { s.enrolOn = true })
	vol := h.v1Install(t, imageA, label, kill)
	s0 := h.probe(t, vol)
	t.Logf("1.0.0 volume after %s: %d files\n%s", map[bool]string{false: "a clean stop", true: "SIGKILL"}[kill], len(s0.Files), strings.Join(s0.Files, "\n"))
	frpc := s0.has("frpc.toml")
	if frpc == !kill {
		t.Errorf("frpc.toml on disk: %v after kill=%v", frpc, kill)
	}
	agent := h.name(label + "-agent")
	h.s.setPhase(label + ":agent")
	t1 := time.Now()
	h.startContainer(t, agent, h.clientSpec(h.agent, vol))
	waitFor(t, 3*time.Minute, "switch", func() bool { return h.seen(since(t1, path("POST", "/device/v2/enroll/confirm", 200))) })
	enrolled := firstAt(h.s.records(), since(t1, path("POST", "/device/v2/enroll", 200)))
	waitFor(t, 2*time.Minute, "app list", func() bool { return h.seen(since(t1, path("GET", "/device/v2/apps", 200))) })
	waitFor(t, time.Minute, "app sync adopted", func() bool {
		return field(agentStatus(t, agent), "app_sync", "adopted") == true
	})
	st := agentStatus(t, agent)
	h.stopContainer(t, agent, false)
	s1 := h.probe(t, vol)
	sameFiles(t, "switched", s0, s1)
	ownerOnly(t, s1)
	if enrolPhase(s1) != "switched" || s1.TokenLen != 0 {
		t.Errorf("enrolment %q, token length %d", enrolPhase(s1), s1.TokenLen)
	}
	if str(field(s1.State, "import", "account_source")) == "" {
		t.Logf("import record: %v", field(s1.State, "import"))
	}
	h.s.mu.Lock()
	apps := make([]serverApp, 0, len(h.s.apps))
	for _, a := range h.s.apps {
		apps = append(apps, *a)
	}
	h.s.mu.Unlock()
	ts := targets(s1)
	t.Logf("targets imported: %v; server apps: %+v; app sync: %v", ts, apps, field(st, "app_sync"))
	if len(apps) != 1 || apps[0].Name != "mock" {
		t.Fatalf("server apps %+v, want the one 1.x app unchanged", apps)
	}
	if frpc {
		if len(ts) != 1 || str(ts[0]["local_id"]) != apps[0].LocalID || apps[0].LocalID == "" {
			t.Errorf("the app in frpc.toml was not adopted: targets %v, server %+v", ts, apps[0])
		}
	} else {
		if len(ts) != 0 || apps[0].LocalID != "" {
			t.Errorf("targets %v, server %+v: want nothing imported and the server app untouched", ts, apps[0])
		}
		// Adoption hides unlinked apps; the next list shows them, here
		// the first list after a restart.
		h.startContainer(t, agent, h.clientSpec(h.agent, vol))
		t2 := time.Now()
		waitFor(t, 2*time.Minute, "app list after restart", func() bool { return h.seen(since(t2, path("GET", "/device/v2/apps", 200))) })
		if un, _ := field(agentStatus(t, agent), "app_sync", "not_linked_to_this_machine").([]any); len(un) != 1 {
			t.Errorf("app sync does not show the 1.x app as not linked: %v", field(st, "app_sync"))
		}
		h.stopContainer(t, agent, false)
		if n := h.count(since(t1, path("POST", "/device/v2/apps", 0))); n != 0 {
			t.Errorf("%d register calls with nothing imported", n)
		}
	}
	h.noV1AfterEnrolment(t, enrolled)
	if n := h.s.frpsConns(label + ":agent"); n != 0 {
		t.Errorf("%d connections to the 1.x frps address from the agent", n)
	}
	h.noFailures(t)
}

func firstAt(rs []rec, f func(rec) bool) time.Time {
	for _, r := range rs {
		if f(r) {
			return r.At
		}
	}
	return time.Time{}
}

func hasToken(rs []rec, t0 time.Time, p, token string) bool {
	for _, r := range rs {
		if r.Agent && !r.At.Before(t0) && r.Path == p {
			return r.Token == token
		}
	}
	return false
}

// noV1AfterEnrolment: 1.x calls and enrol exclude each other, so no 1.x
// call reaches the server after the enrol answer.
func (h *harness) noV1AfterEnrolment(t *testing.T, enrolled time.Time) {
	t.Helper()
	if enrolled.IsZero() {
		t.Fatal("no enrol answer recorded")
	}
	for _, r := range h.s.records() {
		if isAgentV1(r) && r.At.After(enrolled) {
			t.Errorf("1.x call from the agent after enrolment: %s %s %d at %s (enrolled %s)", r.Method, r.Path, r.Status,
				r.At.Format("15:04:05.000"), enrolled.Format("15:04:05.000"))
		}
	}
}
