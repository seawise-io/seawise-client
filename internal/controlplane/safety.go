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
	// DefaultServerDisablesPerDay caps disable requests recorded from the
	// server in any rolling 24 hours.
	DefaultServerDisablesPerDay = 3
	disableWindow               = 24 * time.Hour
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
	NoticePublicImported  NoticeKind = "public_imported"
)

type Notice struct {
	Kind    NoticeKind `json:"kind"`
	LocalID string     `json:"local_id,omitempty"`
	Count   int        `json:"count,omitempty"`
}

// Plan is the only set of local changes a service list can cause. A server
// request to disable an app is recorded for the owner to accept; it never
// turns the app off by itself.
type Plan struct {
	FillSubdomain  map[string]string
	RequestDisable []string
	ClearRequest   []string
	// ServerPublic holds the server's public flag per local ID, for apps
	// whose list item carried one.
	ServerPublic map[string]bool
	Notices      []Notice
}

func (p Plan) Empty() bool {
	return len(p.FillSubdomain) == 0 && len(p.RequestDisable) == 0 && len(p.ClearRequest) == 0 && len(p.ServerPublic) == 0
}

// Apply makes the planned changes on st and reports whether anything
// changed. It re-checks each condition against st, which may have moved on
// since the plan was made. New disable requests are recorded only if the
// whole batch fits in the rolling daily cap.
func (p Plan) Apply(st *store.State, now time.Time, perDay int) (bool, []Notice) {
	changed := false
	var notices []Notice
	byID := map[string]*store.Target{}
	for i := range st.Targets {
		byID[st.Targets[i].LocalID] = &st.Targets[i]
	}
	for id, sub := range p.FillSubdomain {
		if t := byID[id]; t != nil && t.Subdomain == "" && ValidSubdomain(sub) {
			t.Subdomain = sub
			changed = true
		}
	}
	// The server's flag is recorded, never applied: an app is public only
	// with the local toggle. A grandfathered app with no local decision
	// takes the server's flag once, so nothing goes private on upgrade.
	for id, pub := range p.ServerPublic {
		t := byID[id]
		if t == nil {
			continue
		}
		if t.ServerPublic != pub {
			t.ServerPublic = pub
			changed = true
		}
		if t.Public == nil && t.Grandfathered {
			v := pub
			t.Public = &v
			changed = true
			notices = append(notices, Notice{Kind: NoticePublicImported, LocalID: id})
		}
	}
	for _, id := range p.ClearRequest {
		if t := byID[id]; t != nil && t.ServerDisableRequestedAt != nil {
			t.ServerDisableRequestedAt = nil
			changed = true
		}
	}
	recent := st.ServerDisableLog[:0:0]
	for _, at := range st.ServerDisableLog {
		if now.Sub(at) < disableWindow {
			recent = append(recent, at)
		}
	}
	if len(recent) != len(st.ServerDisableLog) {
		st.ServerDisableLog = recent
		changed = true
	}
	var fresh []*store.Target
	for _, id := range p.RequestDisable {
		if t := byID[id]; t != nil && !t.Disabled && t.ServerDisableRequestedAt == nil {
			fresh = append(fresh, t)
		}
	}
	switch {
	case len(fresh) == 0:
	case len(recent)+len(fresh) > perDay:
		notices = append(notices, Notice{Kind: NoticeDisableCap, Count: len(fresh)})
	default:
		for _, t := range fresh {
			at := now
			t.ServerDisableRequestedAt = &at
			st.ServerDisableLog = append(st.ServerDisableLog, now)
		}
		changed = true
	}
	return changed, notices
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
// taken from the server, and a disable is only a request, made after the
// server has repeated it over time.
func PlanServices(local []store.Target, remote []Service, dt *DisableTracker, now time.Time) Plan {
	plan := Plan{FillSubdomain: map[string]string{}, ServerPublic: map[string]bool{}}
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
		if s.Public != nil {
			plan.ServerPublic[t.LocalID] = *s.Public
		}
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
			if !t.Disabled && t.ServerDisableRequestedAt == nil {
				candidates = append(candidates, t.LocalID)
			}
		} else if t.ServerDisableRequestedAt != nil {
			plan.ClearRequest = append(plan.ClearRequest, t.LocalID)
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
	for _, lid := range candidates {
		if dt.confirmed(idOf[lid], now) {
			plan.RequestDisable = append(plan.RequestDisable, lid)
		} else {
			plan.Notices = append(plan.Notices, Notice{Kind: NoticeDisablePending, LocalID: lid})
		}
	}
	sort.Strings(plan.RequestDisable)
	return plan
}
