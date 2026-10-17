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
	p.Apply(&st, t0, DefaultServerDisablesPerDay)
	return st.Targets
}

func TestPlanEmptyList(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter"), target("b", sidB, "10.0.0.3", 80, "brave-seal")}
	p := PlanServices(local, []Service{}, &DisableTracker{}, t0)
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
	p := PlanServices(local, remote, &DisableTracker{}, t0)
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
	p := PlanServices(local, remote, &DisableTracker{}, t0)
	got := apply(local, p)
	if len(got) != 1 || kinds(p)[NoticeUnknown] != 1 {
		t.Fatalf("unknown app imported: %+v %+v", got, p)
	}
}

func TestPlanHostPortNotApplied(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter")}
	remote := []Service{{ID: sidA, Name: "a", Host: "169.254.169.254", Port: 80, Subdomain: "calm-otter"}}
	p := PlanServices(local, remote, &DisableTracker{}, t0)
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
	p := PlanServices(local, remote, &DisableTracker{}, t0)
	got := apply(local, p)
	if got[0].Subdomain != "calm-otter" || got[1].Subdomain != "brave-seal" || kinds(p)[NoticeSubdomainDiffer] != 1 {
		t.Fatalf("subdomain handling: %+v %+v", got, p)
	}
}

func TestPlanUnregisteredUntouched(t *testing.T) {
	local := []store.Target{target("a", "", "10.0.0.2", 80, "")}
	remote := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "disabled"}}
	dt := &DisableTracker{}
	PlanServices(local, remote, dt, t0)
	p := PlanServices(local, remote, dt, t0.Add(time.Hour))
	if got := apply(local, p); !reflect.DeepEqual(got, local) {
		t.Fatalf("matched by name or host: %+v", got)
	}
}

func TestPlanDisableNeedsPersistence(t *testing.T) {
	local := []store.Target{target("a", sidA, "10.0.0.2", 80, "calm-otter")}
	remote := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "disabled"}}
	dt := &DisableTracker{}
	p := PlanServices(local, remote, dt, t0)
	if len(p.RequestDisable) != 0 || kinds(p)[NoticeDisablePending] != 1 {
		t.Fatalf("first report requested: %+v", p)
	}
	p = PlanServices(local, remote, dt, t0.Add(5*time.Minute))
	if len(p.RequestDisable) != 0 {
		t.Fatalf("requested before span: %+v", p)
	}
	enabled := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Status: "online"}}
	PlanServices(local, enabled, dt, t0.Add(6*time.Minute))
	p = PlanServices(local, remote, dt, t0.Add(11*time.Minute))
	if len(p.RequestDisable) != 0 {
		t.Fatalf("clock not restarted: %+v", p)
	}
	p = PlanServices(local, remote, dt, t0.Add(21*time.Minute))
	if !reflect.DeepEqual(p.RequestDisable, []string{"a"}) {
		t.Fatalf("not requested after persistence: %+v", p)
	}
}

func TestServerDisableIsOnlyARequest(t *testing.T) {
	st := store.State{Targets: []store.Target{target("a", sidA, "10.0.0.2", 80, "s-a")}}
	changed, _ := Plan{RequestDisable: []string{"a"}}.Apply(&st, t0, DefaultServerDisablesPerDay)
	a := st.Targets[0]
	if !changed || a.Disabled || a.ServerDisableRequestedAt == nil || len(st.ServerDisableLog) != 1 {
		t.Fatalf("server disable applied directly: %+v", a)
	}
	// The same request again is not counted twice.
	Plan{RequestDisable: []string{"a"}}.Apply(&st, t0.Add(time.Minute), DefaultServerDisablesPerDay)
	if len(st.ServerDisableLog) != 1 {
		t.Fatalf("duplicate request logged: %v", st.ServerDisableLog)
	}
	// The server no longer asking clears the request.
	changed, _ = Plan{ClearRequest: []string{"a"}}.Apply(&st, t0.Add(2*time.Minute), DefaultServerDisablesPerDay)
	if !changed || st.Targets[0].ServerDisableRequestedAt != nil {
		t.Fatal("request not cleared")
	}
}

func TestServerDisableRollingCap(t *testing.T) {
	var targets []store.Target
	ids := []string{"a", "b", "c", "d", "e"}
	sids := []string{sidA, sidB, sidC, "aaaaaaaa-0000-4000-8000-000000000004", "aaaaaaaa-0000-4000-8000-000000000005"}
	for i, id := range ids {
		targets = append(targets, target(id, sids[i], "10.0.0.2", 80, "s-"+id))
	}
	st := store.State{Targets: append([]store.Target(nil), targets...)}
	for i := 0; i < 3; i++ {
		Plan{RequestDisable: []string{ids[i]}}.Apply(&st, t0.Add(time.Duration(i)*time.Hour), 3)
	}
	_, notices := Plan{RequestDisable: []string{"d"}}.Apply(&st, t0.Add(4*time.Hour), 3)
	if st.Targets[3].ServerDisableRequestedAt != nil || kinds(Plan{Notices: notices})[NoticeDisableCap] != 1 {
		t.Fatalf("cap not enforced across syncs: %+v", st.Targets[3])
	}
	// A batch that would exceed the cap records nothing.
	st2 := store.State{Targets: append([]store.Target(nil), targets...)}
	Plan{RequestDisable: ids}.Apply(&st2, t0, 3)
	for _, tg := range st2.Targets {
		if tg.ServerDisableRequestedAt != nil {
			t.Fatal("partial batch over cap recorded")
		}
	}
	Plan{RequestDisable: []string{"d"}}.Apply(&st, t0.Add(25*time.Hour), 3)
	if st.Targets[3].ServerDisableRequestedAt == nil {
		t.Fatal("rolling window did not move on")
	}
	if len(st.ServerDisableLog) > 3 {
		t.Fatalf("log not pruned: %v", st.ServerDisableLog)
	}
}

func TestPlanApplyRechecks(t *testing.T) {
	p := Plan{FillSubdomain: map[string]string{"a": "calm-otter", "b": "Bad_Label"}}
	st := store.State{Targets: []store.Target{target("a", sidA, "h", 80, "already"), target("b", sidB, "h", 80, "")}}
	if changed, _ := p.Apply(&st, t0, DefaultServerDisablesPerDay); changed || st.Targets[0].Subdomain != "already" || st.Targets[1].Subdomain != "" {
		t.Fatalf("apply overwrote or accepted invalid label: %+v", st.Targets)
	}
}

func TestPlanImportsPublicOnlyOnce(t *testing.T) {
	yes, no := true, false
	old := target("a", sidA, "10.0.0.2", 80, "calm-otter")
	old.Grandfathered = true
	fresh := target("b", sidB, "10.0.0.3", 80, "brave-seal")
	local := []store.Target{old, fresh}
	remote := []Service{
		{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Public: &yes},
		{ID: sidB, Name: "b", Host: "10.0.0.3", Port: 80, Subdomain: "brave-seal", Public: &yes},
	}
	p := PlanServices(local, remote, &DisableTracker{}, t0)
	st := store.State{Targets: local}
	changed, notices := p.Apply(&st, t0, DefaultServerDisablesPerDay)
	if !changed {
		t.Fatal("public flags not recorded")
	}
	a, b := st.Targets[0], st.Targets[1]
	if !a.ServerPublic || !a.IsPublicLocally() {
		t.Fatalf("grandfathered public app not imported: %+v", a)
	}
	if !b.ServerPublic || b.Public != nil {
		t.Fatalf("new app made public by the server: %+v", b)
	}
	if len(notices) != 1 || notices[0].Kind != NoticePublicImported || notices[0].LocalID != "a" {
		t.Fatalf("notices = %+v", notices)
	}

	st.Targets[0].Public = &no
	p = PlanServices(st.Targets, remote, &DisableTracker{}, t0)
	p.Apply(&st, t0, DefaultServerDisablesPerDay)
	if st.Targets[0].IsPublicLocally() {
		t.Fatal("server overrode the owner's private toggle")
	}

	remote[0].Public = nil
	p = PlanServices(st.Targets, remote, &DisableTracker{}, t0)
	p.Apply(&st, t0, DefaultServerDisablesPerDay)
	if !st.Targets[0].ServerPublic {
		t.Fatal("missing flag treated as private")
	}
	remote[0].Public = &no
	p = PlanServices(st.Targets, remote, &DisableTracker{}, t0)
	p.Apply(&st, t0, DefaultServerDisablesPerDay)
	if st.Targets[0].ServerPublic {
		t.Fatal("server private flag not recorded")
	}
}

func TestPlanGrandfatheredPrivateImportedAsPrivate(t *testing.T) {
	no := false
	old := target("a", sidA, "10.0.0.2", 80, "calm-otter")
	old.Grandfathered = true
	st := store.State{Targets: []store.Target{old}}
	remote := []Service{{ID: sidA, Name: "a", Host: "10.0.0.2", Port: 80, Subdomain: "calm-otter", Public: &no}}
	PlanServices(st.Targets, remote, &DisableTracker{}, t0).Apply(&st, t0, DefaultServerDisablesPerDay)
	if st.Targets[0].Public == nil || *st.Targets[0].Public {
		t.Fatalf("toggle = %v", st.Targets[0].Public)
	}
	yes := true
	remote[0].Public = &yes
	PlanServices(st.Targets, remote, &DisableTracker{}, t0).Apply(&st, t0, DefaultServerDisablesPerDay)
	if st.Targets[0].IsPublicLocally() {
		t.Fatal("server made a private app public")
	}
}
