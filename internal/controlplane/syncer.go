package controlplane

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/store"
)

var errUnchanged = errors.New("unchanged")

// Agent is the part of the reconcile loop the syncer drives.
type Agent interface {
	Hold(ctx context.Context, reason string) error
	Release(ctx context.Context, reason string) error
	Reconcile(ctx context.Context) error
	Status(ctx context.Context) (agent.Status, error)
	ConnectionID() string
}

type SyncerConfig struct {
	Client     *Client
	Store      *store.Store
	Agent      Agent
	Version    string
	DisableCap int
	// ListEvery is how many heartbeats pass between service list syncs.
	ListEvery int
	Now       func() time.Time
	After     func(time.Duration) <-chan time.Time
	Logger    *slog.Logger
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

	mu     sync.Mutex
	status SyncStatus
}

func NewSyncer(cfg SyncerConfig) (*Syncer, error) {
	if cfg.Client == nil || cfg.Store == nil || cfg.Agent == nil {
		return nil, errors.New("client, store and agent required")
	}
	if cfg.ListEvery <= 0 {
		cfg.ListEvery = 2
	}
	if cfg.DisableCap == 0 {
		cfg.DisableCap = DefaultDisableCap
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

func (s *Syncer) Run(ctx context.Context) error {
	for {
		d := s.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.cfg.After(d):
		}
	}
}

// Step runs one heartbeat, and a list sync when due, and returns the delay
// before the next step.
func (s *Syncer) Step(ctx context.Context) time.Duration {
	st := s.cfg.Store.State()
	if st.Account == nil || s.cfg.Store.Secrets().FRPToken == "" {
		return DefaultBeat
	}
	now := s.cfg.Now()
	hb, err := s.cfg.Client.Heartbeat(ctx, st.Account.ServerID, s.heartbeatRequest(ctx, st))
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
		s.applyEndpoint(ctx, hb)
		s.beats++
		if s.beats%s.cfg.ListEvery == 0 {
			s.syncList(ctx, st.Account.ServerID, now)
		}
		s.update(func(ss *SyncStatus) { ss.Removal = s.removal.State(now) })
		return hb.NextHeartbeat
	case Removal:
		var e *Error
		errors.As(err, &e)
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
	if as, err := s.cfg.Agent.Status(ctx); err == nil && as.Running {
		for _, p := range as.Proxies {
			if strings.EqualFold(p.Status, "running") {
				req.FRPConnected = true
				break
			}
		}
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
	remote, err := s.cfg.Client.ListServices(ctx, serverID)
	if err != nil {
		s.update(func(ss *SyncStatus) { ss.LastError = err.Error() })
		return
	}
	var plan Plan
	changed := false
	err = s.cfg.Store.Update(func(st *store.State) error {
		plan = PlanServices(st.Targets, remote, &s.disables, now, s.cfg.DisableCap)
		if changed = plan.Apply(st); !changed {
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
	if len(plan.Disable) > 0 {
		s.log.Warn("apps disabled at the server's request", "local_ids", plan.Disable)
	}
	if changed {
		_ = s.cfg.Agent.Reconcile(ctx)
	}
}

func (s *Syncer) update(fn func(*SyncStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.status)
}
