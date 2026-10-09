package controlplane

import (
	"reflect"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func TestRemovalNeedsRepeatsOverTime(t *testing.T) {
	var tr RemovalTracker
	if s := tr.State(t0); s.Reported || s.Confirmed {
		t.Fatalf("initial %+v", s)
	}
	tr.Observe(t0, "server_deleted")
	if s := tr.State(t0.Add(time.Hour)); !s.Reported || s.Confirmed {
		t.Fatalf("one report confirmed: %+v", s)
	}
	// Many reports in a burst are not enough.
	for i := 0; i < 10; i++ {
		tr.Observe(t0.Add(time.Duration(i)*time.Second), "server_deleted")
	}
	if s := tr.State(t0.Add(9 * time.Minute)); s.Confirmed {
		t.Fatalf("burst confirmed: %+v", s)
	}
	if s := tr.State(t0.Add(10 * time.Minute)); !s.Confirmed || s.Reason != "server_deleted" {
		t.Fatalf("not confirmed after span: %+v", s)
	}
}

func TestRemovalTwoReportsOverLongSpanNotConfirmed(t *testing.T) {
	var tr RemovalTracker
	tr.Observe(t0, "x")
	tr.Observe(t0.Add(time.Hour), "x")
	if s := tr.State(t0.Add(2 * time.Hour)); s.Confirmed {
		t.Fatalf("two reports confirmed: %+v", s)
	}
}

func TestRemovalResetBySuccess(t *testing.T) {
	var tr RemovalTracker
	tr.Observe(t0, "x")
	tr.Observe(t0.Add(5*time.Minute), "x")
	tr.Reset()
	tr.Observe(t0.Add(11*time.Minute), "x")
	if s := tr.State(t0.Add(12 * time.Minute)); s.Confirmed || s.Count != 1 {
		t.Fatalf("reset ignored: %+v", s)
	}
}

func target(id, sid, host string, port int, sub string) store.Target {
	return store.Target{LocalID: id, Name: id, Host: host, Port: port, ServerServiceID: sid, Subdomain: sub, Source: store.SourceLocal}
}

const (
	sidA = "aaaaaaaa-0000-4000-8000-000000000001"
	sidB = "aaaaaaaa-0000-4000-8000-000000000002"
	sidC = "aaaaaaaa-0000-4000-8000-000000000003"
	sidX = "bbbbbbbb-0000-4000-8000-000000000009"
)

func kinds(p Plan) map[NoticeKind]int {
	out := map[NoticeKind]int{}
	for _, n := range p.Notices {
		out[n.Kind]++
	}
	return out
}

func apply(local []store.Target, p Plan) []store.Target {
	st := store.State{Targets: append([]store.Target(nil), local...)}
	p.Apply(&st)
	return st.Targets
}

func TestPlanEmptyList(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter"), target("b", sidB, "10.0.0.3", 80, "brave-seal")}
	p := PlanServices(local, []Service{}, &DisableTracker{}, t0, DefaultDisableCap)
	if !p.Empty() {
		t.Fatalf("empty list produced changes: %+v", p)
	}
	if k := kinds(p); k[NoticeEmptyList] != 1 || k[NoticeMissing] != 2 {
		t.Fatalf("notices %+v", p.Notices)
	}
	if got := apply(local, p); !reflect.DeepEqual(got, local) {
		t.Fatalf("state changed: %+v", got)
	}
}

func TestPlanAbsenceIsNotDeletion(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter"), target("b", sidB, "10.0.0.3", 80, "brave-seal")}
	remote := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "online"}}
	p := PlanServices(local, remote, &DisableTracker{}, t0, DefaultDisableCap)
	if !p.Empty() || kinds(p)[NoticeMissing] != 1 {
		t.Fatalf("plan %+v", p)
	}
	if got := apply(local, p); !reflect.DeepEqual(got, local) {
		t.Fatalf("state changed: %+v", got)
	}
}

func TestPlanUnknownIgnored(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter")}
	remote := []Service{
		{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter"},
		{ID: sidX, Name: "evil", Host: "203.0.113.5", Port: 443, Subdomain: "phish"},
	}
	p := PlanServices(local, remote, &DisableTracker{}, t0, DefaultDisableCap)
	got := apply(local, p)
	if len(got) != 1 || kinds(p)[NoticeUnknown] != 1 {
		t.Fatalf("unknown app imported: %+v %+v", got, p)
	}
}

func TestPlanHostPortNotApplied(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter")}
	remote := []Service{{ID: sidA, Name: "a", Host: "169.254.169.254", Port: 80, Subdomain: "calm-otter"}}
	p := PlanServices(local, remote, &DisableTracker{}, t0, DefaultDisableCap)
	got := apply(local, p)
	if got[0].Host != "10.0.0.2" || got[0].Port != 80 || kinds(p)[NoticeServerDiffers] != 1 {
		t.Fatalf("server repointed target: %+v %+v", got, p)
	}
}

func TestPlanSubdomainFillOnly(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, ""), target("b", sidB, "10.0.0.3", 80, "brave-seal")}
	remote := []Service{
		{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter"},
		{ID: sidB, Name: "b", Host: "10.0.0.3", Port: 80, Subdomain: "other-name"},
	}
	p := PlanServices(local, remote, &DisableTracker{}, t0, DefaultDisableCap)
	got := apply(local, p)
	if got[0].Subdomain != "calm-otter" || got[1].Subdomain != "brave-seal" || kinds(p)[NoticeSubdomainDiffer] != 1 {
		t.Fatalf("subdomain handling: %+v %+v", got, p)
	}
}

func TestPlanUnregisteredUntouched(t *testing.T) {
	local := []store.Target{target("a", "", "10.0.0.2", 80, "")}
	remote := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "disabled"}}
	dt := &DisableTracker{}
	PlanServices(local, remote, dt, t0, DefaultDisableCap)
	p := PlanServices(local, remote, dt, t0.Add(time.Hour), DefaultDisableCap)
	if got := apply(local, p); !reflect.DeepEqual(got, local) {
		t.Fatalf("matched by name or host: %+v", got)
	}
}

func TestPlanDisableNeedsPersistence(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter")}
	remote := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "disabled"}}
	dt := &DisableTracker{}
	p := PlanServices(local, remote, dt, t0, DefaultDisableCap)
	if len(p.Disable) != 0 || kinds(p)[NoticeDisablePending] != 1 {
		t.Fatalf("first report disabled: %+v", p)
	}
	p = PlanServices(local, remote, dt, t0.Add(5*time.Minute), DefaultDisableCap)
	if len(p.Disable) != 0 {
		t.Fatalf("disabled before span: %+v", p)
	}
	// An enabled report in between restarts the clock.
	enabled := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "online"}}
	PlanServices(local, enabled, dt, t0.Add(6*time.Minute), DefaultDisableCap)
	p = PlanServices(local, remote, dt, t0.Add(11*time.Minute), DefaultDisableCap)
	if len(p.Disable) != 0 {
		t.Fatalf("clock not restarted: %+v", p)
	}
	p = PlanServices(local, remote, dt, t0.Add(21*time.Minute), DefaultDisableCap)
	if !reflect.DeepEqual(p.Disable, []string{"a"}) {
		t.Fatalf("not disabled after persistence: %+v", p)
	}
	got := apply(local, p)
	if !got[0].Disabled || got[0].Host != "10.0.0.2" || len(got) != 1 {
		t.Fatalf("disable applied wrongly: %+v", got)
	}
}

func TestPlanDisableCap(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "s-a"), target("b", sidB, "10.0.0.3", 80, "s-b"), target("c", sidC, "10.0.0.4", 80, "s-c")}
	remote := []Service{
		{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "s-a", Status: "disabled"},
		{ID: sidB, Name: "b", Host: "10.0.0.3", Port: 80, Subdomain: "s-b", Status: "disabled"},
		{ID: sidC, Name: "c", Host: "10.0.0.4", Port: 80, Subdomain: "s-c", Status: "online"},
	}
	dt := &DisableTracker{}
	PlanServices(local, remote, dt, t0, DefaultDisableCap)
	p := PlanServices(local, remote, dt, t0.Add(15*time.Minute), DefaultDisableCap)
	if len(p.Disable) != 0 || kinds(p)[NoticeDisableCap] != 1 {
		t.Fatalf("cap not enforced: %+v", p)
	}
	if got := apply(local, p); got[0].Disabled || got[1].Disabled {
		t.Fatalf("disabled above cap: %+v", got)
	}
	p = PlanServices(local, remote, dt, t0.Add(20*time.Minute), 2)
	if len(p.Disable) != 2 {
		t.Fatalf("within raised cap: %+v", p)
	}
	p = PlanServices(local, remote, dt, t0.Add(25*time.Minute), 0)
	if len(p.Disable) != 0 {
		t.Fatalf("cap 0 disabled: %+v", p)
	}
}

func TestPlanApplyRechecks(t *testing.T) {
	p := Plan{FillSubdomain: map[string]string{"a": "calm-otter", "b": "Bad_Label"}}
	st := store.State{Targets: []store.Target{target("a", sidA, "h", 80, "already"), target("b", sidB, "h", 80, "")}}
	if p.Apply(&st) || st.Targets[0].Subdomain != "already" || st.Targets[1].Subdomain != "" {
		t.Fatalf("apply overwrote or accepted invalid label: %+v", st.Targets)
	}
}
