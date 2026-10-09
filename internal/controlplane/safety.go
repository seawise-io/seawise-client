package controlplane

import (
	"sort"
	"sync"
	"time"

	"github.com/seawise/client/internal/store"
)

const (
	RemovalMinReports = 3
	RemovalMinSpan    = 10 * time.Minute
	DisableMinReports = 2
	DisableMinSpan    = 10 * time.Minute
	DefaultDisableCap = 1
)

// RemovalState describes what the server has said about this machine.
type RemovalState struct {
	Reported  bool      `json:"reported"`
	Count     int       `json:"count"`
	FirstAt   time.Time `json:"first_at,omitzero"`
	Reason    string    `json:"reason,omitempty"`
	Confirmed bool      `json:"confirmed"`
}

// RemovalTracker turns removal reports into a confirmation only after they
// repeat over time with no successful heartbeat in between. It lives in
// memory, so a restart starts the count again.
type RemovalTracker struct {
	mu     sync.Mutex
	count  int
	first  time.Time
	reason string
}

func (t *RemovalTracker) Observe(now time.Time, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count == 0 {
		t.first = now
	}
	t.count++
	t.reason = reason
}

// Reset is called on every successful heartbeat.
func (t *RemovalTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count, t.first, t.reason = 0, time.Time{}, ""
}

func (t *RemovalTracker) State(now time.Time) RemovalState {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count == 0 {
		return RemovalState{}
	}
	return RemovalState{
		Reported: true, Count: t.count, FirstAt: t.first, Reason: t.reason,
		Confirmed: t.count >= RemovalMinReports && now.Sub(t.first) >= RemovalMinSpan,
	}
}

type NoticeKind string

const (
	NoticeEmptyList       NoticeKind = "empty_list"
	NoticeMissing         NoticeKind = "missing_on_server"
	NoticeUnknown         NoticeKind = "unknown_on_server"
	NoticeServerDiffers   NoticeKind = "server_copy_differs"
	NoticeSubdomainDiffer NoticeKind = "subdomain_differs"
	NoticeDisablePending  NoticeKind = "disable_pending"
	NoticeDisableCap      NoticeKind = "disable_cap"
)

type Notice struct {
	Kind    NoticeKind `json:"kind"`
	LocalID string     `json:"local_id,omitempty"`
	Count   int        `json:"count,omitempty"`
}

// Plan is the only set of local changes a service list can cause.
type Plan struct {
	FillSubdomain map[string]string
	Disable       []string
	Notices       []Notice
}

func (p Plan) Empty() bool { return len(p.FillSubdomain) == 0 && len(p.Disable) == 0 }

// Apply makes the planned changes on st and reports whether anything
// changed. It re-checks each condition against st, which may have moved on
// since the plan was made.
func (p Plan) Apply(st *store.State) bool {
	changed := false
	disable := map[string]bool{}
	for _, id := range p.Disable {
		disable[id] = true
	}
	for i := range st.Targets {
		t := &st.Targets[i]
		if sub, ok := p.FillSubdomain[t.LocalID]; ok && t.Subdomain == "" && ValidSubdomain(sub) {
			t.Subdomain = sub
			changed = true
		}
		if disable[t.LocalID] && !t.Disabled {
			t.Disabled = true
			changed = true
		}
	}
	return changed
}

type sighting struct {
	count int
	first time.Time
}

// DisableTracker remembers, per server app ID, since when the server has
// reported the app as disabled.
type DisableTracker struct {
	seen map[string]sighting
}

func (d *DisableTracker) observe(now time.Time, disabled map[string]bool) {
	if d.seen == nil {
		d.seen = map[string]sighting{}
	}
	for id := range d.seen {
		if !disabled[id] {
			delete(d.seen, id)
		}
	}
	for id := range disabled {
		s := d.seen[id]
		if s.count == 0 {
			s.first = now
		}
		s.count++
		d.seen[id] = s
	}
}

func (d *DisableTracker) confirmed(id string, now time.Time) bool {
	s, ok := d.seen[id]
	return ok && s.count >= DisableMinReports && now.Sub(s.first) >= DisableMinSpan
}

// PlanServices compares the local targets with a service list. Matching is by
// the server app ID stored when this client registered the app. Absence is
// never a deletion, unknown apps are never imported, host and port are never
// taken from the server, and disables are capped.
func PlanServices(local []store.Target, remote []Service, dt *DisableTracker, now time.Time, disableCap int) Plan {
	if disableCap < 0 {
		disableCap = 0
	}
	plan := Plan{FillSubdomain: map[string]string{}}
	byID := make(map[string]Service, len(remote))
	for _, s := range remote {
		byID[s.ID] = s
	}
	registered := 0
	matched := map[string]bool{}
	disabledNow := map[string]bool{}
	var candidates []string
	for _, t := range local {
		if t.ServerServiceID == "" {
			continue
		}
		registered++
		s, ok := byID[t.ServerServiceID]
		if !ok {
			plan.Notices = append(plan.Notices, Notice{Kind: NoticeMissing, LocalID: t.LocalID})
			continue
		}
		matched[s.ID] = true
		if s.Host != t.Host || s.Port != t.Port {
			plan.Notices = append(plan.Notices, Notice{Kind: NoticeServerDiffers, LocalID: t.LocalID})
		}
		switch {
		case s.Subdomain == "" || s.Subdomain == t.Subdomain:
		case t.Subdomain == "":
			plan.FillSubdomain[t.LocalID] = s.Subdomain
		default:
			plan.Notices = append(plan.Notices, Notice{Kind: NoticeSubdomainDiffer, LocalID: t.LocalID})
		}
		if s.Status == "disabled" {
			disabledNow[s.ID] = true
			if !t.Disabled {
				candidates = append(candidates, t.LocalID)
			}
		}
	}
	if len(remote) == 0 && registered > 0 {
		plan.Notices = append(plan.Notices, Notice{Kind: NoticeEmptyList, Count: registered})
	}
	if unknown := len(remote) - len(matched); unknown > 0 {
		plan.Notices = append(plan.Notices, Notice{Kind: NoticeUnknown, Count: unknown})
	}

	dt.observe(now, disabledNow)
	idOf := map[string]string{}
	for _, t := range local {
		idOf[t.LocalID] = t.ServerServiceID
	}
	var confirmed []string
	for _, lid := range candidates {
		if dt.confirmed(idOf[lid], now) {
			confirmed = append(confirmed, lid)
		} else {
			plan.Notices = append(plan.Notices, Notice{Kind: NoticeDisablePending, LocalID: lid})
		}
	}
	if len(confirmed) > disableCap {
		plan.Notices = append(plan.Notices, Notice{Kind: NoticeDisableCap, Count: len(confirmed)})
	} else {
		sort.Strings(confirmed)
		plan.Disable = confirmed
	}
	return plan
}
