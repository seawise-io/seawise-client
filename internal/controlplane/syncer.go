package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/store"
)

var errUnchanged = errors.New("unchanged")

// DefaultListEvery is how many heartbeats pass between service list syncs
// (15 minutes at the usual 30 s heartbeat). The list only carries disable
// requests and public flags; new apps get their subdomain from the
// register reply. The first list sync runs on the first heartbeat.
const DefaultListEvery = 30

// DefaultOfflineTimeout keeps the offline call inside Docker's default
// 10 s stop grace period.
const DefaultOfflineTimeout = 5 * time.Second

// Agent is the part of the reconcile loop the syncer drives.
type Agent interface {
	Hold(ctx context.Context, reason string) error
	Release(ctx context.Context, reason string) error
	Reconcile(ctx context.Context) error
	Status(ctx context.Context) (agent.Status, error)
	ConnectionID() string
}

type SyncerConfig struct {
	Client  *Client
	Store   *store.Store
	Agent   Agent
	Version string
	// ServerDisablesPerDay caps disable requests recorded per rolling day.
	ServerDisablesPerDay int
	// ListEvery is how many heartbeats pass between service list syncs.
	ListEvery int
	// SkipList reports that the v2 app sync owns the app list.
	SkipList func() bool
	// Legacy reports whether 1.x calls may still use the token; it turns
	// false once the device key is enrolled.
	Legacy func() bool
	// Gate is shared with enrolment: every 1.x call holds it for reading
	// from its Legacy check until its answer, enrolment holds it for
	// writing while an enroll is in flight. Nil for none.
	Gate *sync.RWMutex
	// OfflineTimeout bounds the offline call sent when Run stops.
	OfflineTimeout time.Duration
	Now            func() time.Time
	After          func(time.Duration) <-chan time.Time
	Logger         *slog.Logger
}

type SyncStatus struct {
	LastHeartbeat time.Time    `json:"last_heartbeat,omitzero"`
	LastError     string       `json:"last_error,omitempty"`
	Removal       RemovalState `json:"removal"`
	Superseded    bool         `json:"superseded"`
	Notices       []Notice     `json:"notices,omitempty"`
}

type Syncer struct {
	cfg      SyncerConfig
	log      *slog.Logger
	removal  RemovalTracker
	disables DisableTracker
	beats    int
	failures int
	held     bool
	// online is true after a 200 heartbeat until a removal or superseded
	// answer.
	online bool

	mu     sync.Mutex
	status SyncStatus
}

func NewSyncer(cfg SyncerConfig) (*Syncer, error) {
	if cfg.Client == nil || cfg.Store == nil || cfg.Agent == nil {
		return nil, errors.New("client, store and agent required")
	}
	if cfg.ListEvery <= 0 {
		cfg.ListEvery = DefaultListEvery
	}
	if cfg.ServerDisablesPerDay <= 0 {
		cfg.ServerDisablesPerDay = DefaultServerDisablesPerDay
	}
	if cfg.OfflineTimeout <= 0 {
		cfg.OfflineTimeout = DefaultOfflineTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Syncer{cfg: cfg, log: cfg.Logger.With("component", "controlplane")}, nil
}

func (s *Syncer) Status() SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.status
	out.Notices = append([]Notice(nil), s.status.Notices...)
	return out
}

// Run heartbeats until ctx ends, then tells the server this machine is
// going offline, as 1.x does on a clean stop.
func (s *Syncer) Run(ctx context.Context) error {
	for {
		d := s.Step(ctx)
		select {
		case <-ctx.Done():
			s.goOffline(ctx)
			return ctx.Err()
		case <-s.cfg.After(d):
		}
	}
}

func (s *Syncer) rlock() func() {
	if s.cfg.Gate == nil {
		return func() {}
	}
	s.cfg.Gate.RLock()
	return s.cfg.Gate.RUnlock
}

// legacy reports whether 1.x calls may use the stored token.
func (s *Syncer) legacy(st store.State) bool {
	return st.Account != nil && s.cfg.Store.Secrets().FRPToken != "" && (s.cfg.Legacy == nil || s.cfg.Legacy())
}

// goOffline sends one offline call while the 1.x token is still in use and
// this run was the server's live connection.
func (s *Syncer) goOffline(parent context.Context) {
	unlock := s.rlock()
	defer unlock()
	st := s.cfg.Store.State()
	if !s.online || !s.legacy(st) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.cfg.OfflineTimeout)
	defer cancel()
	if err := s.cfg.Client.MarkOffline(ctx, st.Account.ServerID); err != nil {
		s.log.Warn("offline notice not sent", "error", err)
	}
}

// Step runs one heartbeat, and a list sync when due, and returns the delay
// before the next step.
func (s *Syncer) Step(ctx context.Context) time.Duration {
	st := s.cfg.Store.State()
	if !s.legacy(st) {
		return DefaultBeat
	}
	now := s.cfg.Now()
	req := s.heartbeatRequest(ctx, st)
	unlock := s.rlock()
	// Enrolment may have finished while the request was built.
	if !s.legacy(s.cfg.Store.State()) {
		unlock()
		return DefaultBeat
	}
	hb, err := s.cfg.Client.Heartbeat(ctx, st.Account.ServerID, req)
	unlock()
	switch KindOf(err) {
	case 0:
		s.failures = 0
		s.removal.Reset()
		s.update(func(ss *SyncStatus) { ss.LastHeartbeat, ss.LastError, ss.Superseded = now, "", false })
		if s.held {
			if err := s.cfg.Agent.Release(ctx, agent.HoldRemoval); err == nil {
				s.held = false
				s.log.Info("server reports this machine again; tunnels resumed")
			}
		}
		s.online = true
		s.applyEndpoint(ctx, hb)
		s.beats++
		if (s.beats-1)%s.cfg.ListEvery == 0 && (s.cfg.SkipList == nil || !s.cfg.SkipList()) {
			s.syncList(ctx, st.Account.ServerID, now)
		}
		s.update(func(ss *SyncStatus) { ss.Removal = s.removal.State(now) })
		return hb.NextHeartbeat
	case Removal:
		var e *Error
		errors.As(err, &e)
		s.online = false
		s.removal.Observe(now, e.Reason)
		rs := s.removal.State(now)
		s.update(func(ss *SyncStatus) { ss.Removal, ss.LastError = rs, err.Error() })
		s.log.Warn("server reports removal", "count", rs.Count, "reason", e.Reason, "confirmed", rs.Confirmed)
		if rs.Confirmed && !s.held {
			if err := s.cfg.Agent.Hold(ctx, agent.HoldRemoval); err == nil {
				s.held = true
				s.log.Warn("removal reported repeatedly; tunnels held, local state kept")
			}
		}
		return DefaultBeat
	case Superseded:
		s.online = false
		s.update(func(ss *SyncStatus) { ss.Superseded, ss.LastError = true, err.Error() })
		return DefaultBeat
	default:
		s.failures++
		s.update(func(ss *SyncStatus) { ss.LastError = err.Error() })
		return min(time.Second<<min(s.failures-1, 5), 30*time.Second)
	}
}

func (s *Syncer) heartbeatRequest(ctx context.Context, st store.State) HeartbeatRequest {
	req := HeartbeatRequest{ClientVersion: s.cfg.Version, ConnectionID: s.cfg.Agent.ConnectionID()}
	for _, t := range st.Targets {
		if !t.Disabled && t.Subdomain != "" {
			req.ServiceCount++
		}
	}
	if as, err := s.cfg.Agent.Status(ctx); err == nil {
		req.FRPConnected = as.Connected
	}
	return req
}

func (s *Syncer) applyEndpoint(ctx context.Context, hb *Heartbeat) {
	ep := hb.MigrateTo
	if ep == nil {
		ep = hb.Shard
	}
	if ep == nil {
		return
	}
	changed := false
	err := s.cfg.Store.Update(func(st *store.State) error {
		if st.Account == nil || (st.Account.FRPServerAddr == ep.Addr && st.Account.FRPServerPort == ep.Port) {
			return errUnchanged
		}
		st.Account.FRPServerAddr, st.Account.FRPServerPort = ep.Addr, ep.Port
		changed = true
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotDurable) && !errors.Is(err, errUnchanged) {
		s.log.Warn("store frp server", "error", err)
		return
	}
	if changed {
		s.log.Info("frp server changed by heartbeat", "addr", ep.Addr, "port", ep.Port)
		_ = s.cfg.Agent.Reconcile(ctx)
	}
}

func (s *Syncer) syncList(ctx context.Context, serverID string, now time.Time) {
	unlock := s.rlock()
	if !s.legacy(s.cfg.Store.State()) {
		unlock()
		return
	}
	remote, err := s.cfg.Client.ListServices(ctx, serverID)
	unlock()
	if err != nil {
		s.update(func(ss *SyncStatus) { ss.LastError = err.Error() })
		return
	}
	var plan Plan
	changed := false
	err = s.cfg.Store.Update(func(st *store.State) error {
		plan = PlanServices(st.Targets, remote, &s.disables, now)
		var notices []Notice
		changed, notices = plan.Apply(st, now, s.cfg.ServerDisablesPerDay)
		plan.Notices = append(plan.Notices, notices...)
		if !changed {
			return errUnchanged
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotDurable) && !errors.Is(err, errUnchanged) {
		s.log.Warn("store service list", "error", err)
		return
	}
	s.update(func(ss *SyncStatus) { ss.Notices = plan.Notices })
	for _, n := range plan.Notices {
		if n.Kind == NoticeEmptyList || n.Kind == NoticeDisableCap || n.Kind == NoticeUnknown {
			s.log.Warn("service list ignored in part", "notice", n.Kind, "count", n.Count)
		}
	}
	if len(plan.RequestDisable) > 0 {
		s.log.Warn("server asks to turn off apps; waiting for local confirmation", "local_ids", plan.RequestDisable)
	}
	if changed && (len(plan.FillSubdomain) > 0 || len(plan.ServerPublic) > 0) {
		_ = s.cfg.Agent.Reconcile(ctx)
	}
}

func (s *Syncer) update(fn func(*SyncStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.status)
}
