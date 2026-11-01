package appsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/store"
)

const (
	DefaultListEvery   = 15 * time.Minute
	DefaultCallTimeout = 15 * time.Second
	MaxBackoff         = 30 * time.Second
	idleWait           = 30 * time.Second
)

// Modes and results shown in Status.
const (
	ModeOff = "off"
	ModeV2  = "v2"

	ResultOK       = "ok"
	ResultRetrying = "retrying"
	ResultRefused  = "refused"
	ResultIdentity = "identity"
)

var (
	errUnchanged    = errors.New("unchanged")
	errListTooLarge = errors.New("list: too large")
)

// Errors of Add and Remove.
var (
	ErrInvalidApp  = errors.New("invalid app")
	ErrNameExists  = errors.New("an app with this name exists")
	ErrTooManyApps = errors.New("too many apps")
	ErrNoSuchApp   = errors.New("no such app")
	ErrOutboxFull  = errors.New("outbox full; try again after the next sync")
)

type Config struct {
	Store   *store.Store
	Carrier Carrier
	Now     func() time.Time
	// Rand jitters a backoff delay; the default picks from [d/2, d].
	Rand        func(time.Duration) time.Duration
	Logger      *slog.Logger
	ListEvery   time.Duration
	CallTimeout time.Duration
	// OnIdentity runs identity recovery when the server refuses the
	// device's proof (invalid_proof, key_revoked); it is never a call
	// answer. A returned error is shown in the status.
	OnIdentity func(ctx context.Context, code string) error
	// OnChange runs after the local app list changed.
	OnChange func(ctx context.Context)
}

// Refusal is an app the server or the local grammar refused.
type Refusal struct {
	LocalID string `json:"local_id"`
	Reason  string `json:"reason"`
}

// Unlinked is a server app not linked to this machine.
type Unlinked struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Status struct {
	Mode            string     `json:"mode"`
	Adopted         bool       `json:"adopted"`
	OutboxDepth     int        `json:"outbox_depth"`
	OldestCall      time.Time  `json:"oldest_call,omitzero"`
	HeadAttempts    int        `json:"head_attempts"`
	LastSync        time.Time  `json:"last_sync,omitzero"`
	LastResult      string     `json:"last_result,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	Refused         []Refusal  `json:"refused,omitempty"`
	Unlinked        []Unlinked `json:"not_linked_to_this_machine,omitempty"`
	UnknownOnServer int        `json:"unknown_on_server,omitempty"`
	Notices         []string   `json:"notices,omitempty"`
}

type refusal struct {
	reason string
	until  time.Time
}

type relink struct {
	localID, name string
}

// Engine runs the app sync of one agent. Step is called from one goroutine;
// Add, Remove, SetHealth, Kick and Status may be called from any.
type Engine struct {
	cfg  Config
	log  *slog.Logger
	path string
	kick chan struct{}

	mu           sync.Mutex
	box          File
	attempts     int
	failures     int
	nonceRetried bool
	waitUntil    time.Time
	nextList     time.Time
	listNow      bool
	refused      map[string]refusal
	split        map[string]bool
	relinks      []relink
	health       map[string]string
	healthGen    int
	healthSent   int
	changed      bool
	status       Status

	failRemoveTarget bool
	saveHook         func() error
}

func New(cfg Config) (*Engine, error) {
	if cfg.Store == nil || cfg.Carrier == nil {
		return nil, errors.New("appsync: store and carrier required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = func(d time.Duration) time.Duration { return d/2 + rand.N(d/2+1) }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ListEvery <= 0 {
		cfg.ListEvery = DefaultListEvery
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = DefaultCallTimeout
	}
	e := &Engine{
		cfg: cfg, log: cfg.Logger.With("component", "appsync"), path: filepath.Join(cfg.Store.Dir(), OutboxFile),
		kick: make(chan struct{}, 1), refused: map[string]refusal{}, split: map[string]bool{},
		status: Status{Mode: ModeOff},
	}
	f, ok, err := loadFile(e.path)
	if err != nil {
		return nil, err
	}
	if !ok {
		f = emptyFile("")
	}
	e.box = f
	return e, nil
}

// Kick asks for a list sync soon, after a local change.
func (e *Engine) Kick() {
	e.mu.Lock()
	e.listNow = true
	e.mu.Unlock()
	e.wake()
}

func (e *Engine) wake() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Run steps the engine while active reports true.
func (e *Engine) Run(ctx context.Context, active func() bool) error {
	for {
		d := idleWait
		if active == nil || active() {
			d = e.Step(ctx)
		} else {
			e.mu.Lock()
			e.status.Mode = ModeOff
			e.mu.Unlock()
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		case <-e.kick:
			t.Stop()
		}
	}
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.status
	s.Adopted = e.box.Adopted
	s.OutboxDepth = len(e.box.Calls)
	if len(e.box.Calls) > 0 {
		s.OldestCall = e.box.Calls[0].CreatedAt
	}
	s.HeadAttempts = e.attempts
	s.Refused = nil
	for id, r := range e.refused {
		s.Refused = append(s.Refused, Refusal{LocalID: id, Reason: r.reason})
	}
	if e.box.Adopted {
		for _, r := range e.box.Retired {
			if _, ok := e.refused[r.LocalID]; !ok {
				s.Refused = append(s.Refused, Refusal{LocalID: r.LocalID, Reason: "removed here but not linked on the server"})
			}
		}
	}
	sort.Slice(s.Refused, func(i, j int) bool { return s.Refused[i].LocalID < s.Refused[j].LocalID })
	s.Unlinked = slices.Clone(e.status.Unlinked)
	s.Notices = slices.Clone(e.status.Notices)
	return s
}

// idle reports whether nothing is due before the next scheduled list.
func (e *Engine) idle() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	return len(e.box.Calls) == 0 && e.box.Adopted && e.healthGen == e.healthSent && !e.listNow && now.Before(e.nextList)
}

func (e *Engine) save() error {
	if e.saveHook != nil {
		if err := e.saveHook(); err != nil {
			return err
		}
	}
	if e.box.Calls == nil {
		e.box.Calls = []Call{}
	}
	if e.box.Registered == nil {
		e.box.Registered = []string{}
	}
	if e.box.Deleted == nil {
		e.box.Deleted = []string{}
	}
	if err := saveFile(e.path, &e.box); err != nil {
		e.log.Error("write outbox", "error", err)
		e.status.LastError = "could not write the outbox: " + err.Error()
		return err
	}
	return nil
}

func persisted(err error) error {
	if errors.Is(err, store.ErrNotDurable) || errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// Step does one unit of work and returns the delay before the next.
func (e *Engine) Step(ctx context.Context) time.Duration {
	d := e.step(ctx)
	e.mu.Lock()
	changed := e.changed
	e.changed = false
	e.mu.Unlock()
	if changed && e.cfg.OnChange != nil {
		e.cfg.OnChange(ctx)
	}
	return d
}

func (e *Engine) step(ctx context.Context) time.Duration {
	st := e.cfg.Store.State()
	if st.Account == nil || !ValidLocalID(st.Account.ServerID) {
		e.mu.Lock()
		e.status.Mode = ModeOff
		e.mu.Unlock()
		return idleWait
	}
	now := e.cfg.Now()
	e.mu.Lock()
	e.status.Mode = ModeV2
	if err := e.bindServer(st.Account.ServerID); err != nil {
		e.status.LastError = err.Error()
		e.mu.Unlock()
		return MaxBackoff
	}
	if _, err := e.prepare(); err != nil {
		e.status.LastError = err.Error()
		e.mu.Unlock()
		return MaxBackoff
	}
	if now.Before(e.waitUntil) {
		e.mu.Unlock()
		return e.waitUntil.Sub(now)
	}
	adopting := !e.box.Adopted && !e.hasAdopt()
	switch {
	case adopting:
		if now.Before(e.nextList) && !e.listNow {
			e.mu.Unlock()
			return e.nextList.Sub(now)
		}
		e.mu.Unlock()
		return e.syncList(ctx, now, true)
	case len(e.box.Calls) > 0:
		e.mu.Unlock()
		return e.sendHead(ctx, now)
	case e.healthGen != e.healthSent:
		e.mu.Unlock()
		return e.sendHealth(ctx, now)
	case e.listNow || !now.Before(e.nextList):
		e.mu.Unlock()
		return e.syncList(ctx, now, false)
	}
	d := e.nextList.Sub(now)
	e.mu.Unlock()
	return d
}

func (e *Engine) hasAdopt() bool {
	return slices.ContainsFunc(e.box.Calls, func(c Call) bool { return c.Adopt })
}

// prepare gives every target a UUID local_id and drops targets whose
// local_id was deleted (a delete interrupted between its two writes). It
// returns the replaced ids.
func (e *Engine) prepare() (map[string]string, error) {
	deleted := map[string]bool{}
	for _, id := range e.box.Deleted {
		deleted[id] = true
	}
	renamed := map[string]string{}
	changed := false
	err := e.cfg.Store.Update(func(s *store.State) error {
		n := len(s.Targets)
		s.Targets = slices.DeleteFunc(s.Targets, func(t store.Target) bool { return deleted[t.LocalID] })
		changed = len(s.Targets) != n
		for i := range s.Targets {
			if !ValidLocalID(s.Targets[i].LocalID) {
				id := NewLocalID()
				renamed[s.Targets[i].LocalID] = id
				s.Targets[i].LocalID = id
				changed = true
			}
		}
		if !changed {
			return errUnchanged
		}
		return nil
	})
	if err := persisted(err); err != nil {
		return nil, fmt.Errorf("prepare local apps: %w", err)
	}
	e.changed = e.changed || changed
	return renamed, nil
}

func (e *Engine) backoff(now time.Time, retryAfter time.Duration, why string) time.Duration {
	e.failures++
	d := min(time.Second<<min(e.failures-1, 6), MaxBackoff)
	d = e.cfg.Rand(d)
	if retryAfter > d {
		d = min(retryAfter, MaxBackoff)
	}
	e.waitUntil = now.Add(d)
	e.status.LastError = why
	return d
}

func (e *Engine) succeeded() {
	e.failures, e.attempts, e.nonceRetried, e.waitUntil = 0, 0, false, time.Time{}
}

func (e *Engine) call(ctx context.Context, r Request) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.CallTimeout)
	defer cancel()
	return e.cfg.Carrier.Do(ctx, r)
}

// transientStatus reports answers whose outcome is unknown.
func transientStatus(code int) bool {
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500 || (code >= 300 && code < 400)
}

func (e *Engine) sendHead(ctx context.Context, now time.Time) time.Duration {
	e.mu.Lock()
	c := e.box.Calls[0]
	if c.Op == OpDelete && !slices.ContainsFunc(c.LocalIDs, func(id string) bool { return slices.Contains(e.box.Registered, id) }) {
		// Never confirmed by the server: nothing to delete there.
		e.box.Calls = e.box.Calls[1:]
		_ = e.save()
		e.mu.Unlock()
		return 0
	}
	e.mu.Unlock()
	method := pb.DeviceMethod_REGISTER_APPS
	if c.Op == OpDelete {
		method = pb.DeviceMethod_DELETE_APPS
	}
	resp, err := e.call(ctx, Request{Method: method, Key: c.Key, Body: c.Body})

	e.mu.Lock()
	defer e.mu.Unlock()
	e.attempts++
	if err != nil {
		e.nonceRetried = false
		e.status.LastResult = ResultRetrying
		return e.backoff(now, 0, c.Op+": outcome unknown: "+err.Error())
	}
	eb := parseError(resp.Body)
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		if err := e.apply(c, resp.Body); err != nil {
			e.status.LastResult = ResultRetrying
			return e.backoff(now, 0, err.Error())
		}
		e.succeeded()
		e.status.LastResult, e.status.LastError = ResultOK, ""
		return 0
	case resp.Status == http.StatusUnauthorized && (resp.NonceChallenge || eb.Error == "use_dpop_nonce"):
		e.status.LastResult = ResultRetrying
		if !e.nonceRetried {
			e.nonceRetried = true
			return 0
		}
		return e.backoff(now, 0, c.Op+": nonce challenge repeated")
	case resp.Status == http.StatusUnauthorized && eb.Code == "replayed":
		e.nonceRetried = false
		e.status.LastResult = ResultRetrying
		return e.backoff(now, 0, c.Op+": proof replayed, outcome unknown")
	case resp.Status == http.StatusUnauthorized:
		e.nonceRetried = false
		code := eb.Code
		if code == "" {
			code = "invalid_proof"
		}
		e.log.Warn("device proof refused; identity recovery needed", "code", code)
		why := c.Op + ": device proof refused: " + code
		e.mu.Unlock()
		err := e.identity(ctx, code)
		e.mu.Lock()
		if err != nil {
			why += ": " + err.Error()
		}
		e.status.LastResult = ResultIdentity
		return e.backoff(now, 0, why)
	case transientStatus(resp.Status):
		e.nonceRetried = false
		e.status.LastResult = ResultRetrying
		return e.backoff(now, resp.RetryAfter, fmt.Sprintf("%s: status %d", c.Op, resp.Status))
	}
	e.nonceRetried = false
	e.succeeded()
	switch {
	case resp.Status == http.StatusConflict && eb.Error == "idempotency_mismatch":
		e.log.Error("idempotency_mismatch: a queued call changed under its key; dropped", "op", c.Op, "local_ids", c.LocalIDs)
		e.dropHead(c)
		e.listNow = true
		e.status.LastError = c.Op + ": idempotency_mismatch"
	case resp.Status == http.StatusConflict && eb.Error == "name_taken" && c.Op == OpRegister:
		lid := eb.LocalID
		if lid == "" && eb.Index != nil && *eb.Index >= 0 && *eb.Index < len(c.LocalIDs) {
			lid = c.LocalIDs[*eb.Index]
		}
		if i := slices.Index(c.LocalIDs, lid); i >= 0 {
			var b registerBody
			_ = json.Unmarshal(c.Body, &b)
			e.relinks = append(e.relinks, relink{localID: lid, name: b.Apps[i].Name})
		} else {
			for _, id := range c.LocalIDs {
				e.refused[id] = refusal{reason: "name_taken", until: now.Add(e.cfg.ListEvery)}
			}
		}
		e.log.Info("app name taken on the server; relinking from the app list", "local_id", lid)
		e.dropHead(c)
		e.listNow = true
		e.status.LastResult, e.status.LastError = ResultRefused, "register: name_taken"
	default:
		reason := eb.Error
		if reason == "" {
			reason = fmt.Sprintf("status %d", resp.Status)
		}
		e.log.Warn("call refused by the server", "op", c.Op, "status", resp.Status, "reason", reason, "local_ids", c.LocalIDs)
		for _, id := range c.LocalIDs {
			e.refused[id] = refusal{reason: reason, until: now.Add(e.cfg.ListEvery)}
		}
		if c.Op == OpRegister && len(c.LocalIDs) > 1 {
			for _, id := range c.LocalIDs {
				e.split[id] = true
				e.refused[id] = refusal{reason: reason}
			}
			e.listNow = true
		}
		e.box.Calls = e.box.Calls[1:]
		if c.Adopt && !e.hasAdopt() {
			e.markAdopted()
		}
		_ = e.save()
		e.status.LastResult, e.status.LastError = ResultRefused, c.Op+": "+reason
	}
	return 0
}

// bindServer starts a fresh outbox when the paired server changed.
func (e *Engine) bindServer(serverID string) error {
	if e.box.ServerID == serverID {
		return nil
	}
	st := e.cfg.Store.State()
	imported := st.Import != nil && st.Import.ServerID == serverID
	if e.box.ServerID == "" && imported {
		// First binding to the 1.x account: keep what was queued.
		e.box.ServerID = serverID
		return e.save()
	}
	// Another server: registrations of the old one mean nothing there, as
	// 1.x's clearServerRegistrations did on re-pairing.
	err := e.cfg.Store.Update(func(s *store.State) error {
		for i := range s.Targets {
			s.Targets[i].ServerServiceID, s.Targets[i].Subdomain = "", ""
		}
		return nil
	})
	if err := persisted(err); err != nil {
		return err
	}
	e.changed = true
	if e.box.ServerID == "" {
		e.box.ServerID, e.box.Retired = serverID, nil
		return e.save()
	}
	e.box = emptyFile(serverID)
	e.attempts, e.failures, e.waitUntil, e.nextList = 0, 0, time.Time{}, time.Time{}
	e.refused, e.split, e.relinks = map[string]refusal{}, map[string]bool{}, nil
	e.status = Status{Mode: ModeV2}
	return e.save()
}

// identity runs the recovery callback; the caller does not hold e.mu.
func (e *Engine) identity(ctx context.Context, code string) error {
	if e.cfg.OnIdentity == nil {
		return nil
	}
	return e.cfg.OnIdentity(ctx, code)
}

// Listed reports whether a v2 list of the paired server succeeded, so the
// v2 sync owns the app list.
func (e *Engine) Listed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	acc := e.cfg.Store.State().Account
	return acc != nil && acc.ServerID == e.box.ServerID && !e.status.LastSync.IsZero()
}

func (e *Engine) markAdopted() {
	e.box.Adopted = true
	e.log.Info("first v2 app sync done")
}

func (e *Engine) isRetired(id string) bool {
	return slices.ContainsFunc(e.box.Retired, func(r Retired) bool { return r.LocalID == id })
}

// dropHead drops the head call; a dropped adoption call restarts adoption,
// so the queued adoption calls that were never sent are dropped too.
func (e *Engine) dropHead(c Call) {
	e.box.Calls = e.box.Calls[1:]
	if c.Adopt {
		e.box.Calls = slices.DeleteFunc(e.box.Calls, func(c Call) bool { return c.Adopt })
	}
	_ = e.save()
}

// apply records a 2xx answer: the local state first, then the outbox, so a
// crash in between replays the call and gets the stored answer again.
func (e *Engine) apply(c Call, raw []byte) error {
	if c.Op == OpDelete {
		unrecorded, err := parseDeleteAnswer(raw, c.LocalIDs)
		if err != nil {
			return err
		}
		for _, id := range c.LocalIDs {
			e.box.Registered = removeID(e.box.Registered, id)
		}
		for _, id := range unrecorded {
			e.log.Warn("app gone on the server, which recorded no tombstone", "local_id", id)
			e.status.Notices = append(e.status.Notices, "delete_not_recorded_by_server:"+id)
		}
		e.box.Calls = e.box.Calls[1:]
		return e.save()
	}
	res, err := parseRegisterAnswer(raw, c.LocalIDs)
	if err != nil {
		return err
	}
	auth := e.cfg.Carrier.Authenticated()
	var sent registerBody
	_ = json.Unmarshal(c.Body, &sent)
	changed := false
	var notices []string
	err = e.cfg.Store.Update(func(s *store.State) error {
		for k, r := range res {
			i := slices.IndexFunc(s.Targets, func(t store.Target) bool { return t.LocalID == r.LocalID })
			if i < 0 {
				continue
			}
			t := &s.Targets[i]
			switch {
			case r.Result == resDeleted && !auth:
				notices = append(notices, "server_reports_deleted:"+r.LocalID)
			case r.Result == resDeleted:
				s.Targets = slices.Delete(s.Targets, i, i+1)
				changed = true
			default:
				// Adoption sent the listed name of a 1.x app; keep it now.
				if c.Adopt && k < len(sent.Apps) && t.Name != sent.Apps[k].Name && t.ServerServiceID == r.ID {
					t.Name = sent.Apps[k].Name
					changed = true
				}
				if t.ServerServiceID != r.ID {
					t.ServerServiceID = r.ID
					changed = true
				}
				if t.Subdomain == "" {
					t.Subdomain = r.Subdomain
					changed = true
				} else if t.Subdomain != r.Subdomain {
					notices = append(notices, "subdomain_differs:"+r.LocalID)
				}
			}
		}
		if !changed {
			return errUnchanged
		}
		return nil
	})
	if err := persisted(err); err != nil {
		return fmt.Errorf("record register answer: %w", err)
	}
	e.changed = e.changed || changed
	for _, r := range res {
		delete(e.refused, r.LocalID)
		delete(e.split, r.LocalID)
		if i := slices.IndexFunc(e.box.Retired, func(x Retired) bool { return x.LocalID == r.LocalID }); i >= 0 && (r.Result == resUpdated || r.Result == resUnchanged) && r.ID != e.box.Retired[i].ServerID {
			// Adopted another server app than the one removed here: never
			// delete it. An app created by this register is ours and its
			// queued delete removes it.
			e.log.Warn("removed app adopted another server app; not deleted", "local_id", r.LocalID)
			e.box.Retired = slices.Delete(e.box.Retired, i, i+1)
			e.box.Deleted = removeID(e.box.Deleted, r.LocalID)
			continue
		}
		e.box.Retired = slices.DeleteFunc(e.box.Retired, func(x Retired) bool { return x.LocalID == r.LocalID })
		if r.Result == resDeleted && !auth {
			continue
		}
		if r.Result == resDeleted {
			e.box.Deleted = addID(e.box.Deleted, r.LocalID, maxDeleted)
			e.box.Registered = removeID(e.box.Registered, r.LocalID)
			e.log.Info("app deleted on the server; removed here", "local_id", r.LocalID)
			continue
		}
		e.box.Registered = addID(e.box.Registered, r.LocalID, maxRegistered)
	}
	e.box.Calls = e.box.Calls[1:]
	if c.Adopt && !e.hasAdopt() {
		e.markAdopted()
	}
	e.status.Notices = notices
	return e.save()
}

func (e *Engine) fetchList(ctx context.Context) (listAnswer, error) {
	resp, err := e.call(ctx, Request{Method: pb.DeviceMethod_LIST_APPS})
	if err == nil && resp.NonceChallenge {
		resp, err = e.call(ctx, Request{Method: pb.DeviceMethod_LIST_APPS})
	}
	if err != nil {
		return listAnswer{}, fmt.Errorf("list: outcome unknown: %w", err)
	}
	if resp.Status != http.StatusOK {
		eb := parseError(resp.Body)
		if resp.Status == http.StatusRequestEntityTooLarge && eb.Error == "list_too_large" {
			return listAnswer{}, errListTooLarge
		}
		if resp.Status == http.StatusUnauthorized && eb.Code != "" && eb.Code != "replayed" && !resp.NonceChallenge && eb.Error != "use_dpop_nonce" {
			if err := e.identity(ctx, eb.Code); err != nil {
				return listAnswer{}, fmt.Errorf("list: device proof refused: %s: %w", eb.Code, err)
			}
		}
		return listAnswer{}, fmt.Errorf("list: status %d", resp.Status)
	}
	return parseList(resp.Body)
}

// syncList lists the server's apps and derives the calls that bring the
// server in line with the local list. Absence never deletes anything.
func (e *Engine) syncList(ctx context.Context, now time.Time, adopting bool) time.Duration {
	l, err := e.fetchList(ctx)
	e.mu.Lock()
	defer e.mu.Unlock()
	if errors.Is(err, ErrAnswerTooLarge) {
		e.status.LastResult = ResultRetrying
		e.status.LastError = "the app list from the server is over 64 KiB; retrying at the next list"
		e.log.Error("app list answer over 64 KiB")
		e.waitUntil = now.Add(e.cfg.ListEvery)
		return e.cfg.ListEvery
	}
	if errors.Is(err, errListTooLarge) {
		e.status.LastResult = ResultRetrying
		e.status.LastError = "the server's app list is too large to send; retrying at the next list"
		e.log.Error("app list too large on the server")
		e.waitUntil = now.Add(e.cfg.ListEvery)
		return e.cfg.ListEvery
	}
	if err != nil {
		e.status.LastResult = ResultRetrying
		return e.backoff(now, 0, err.Error())
	}
	e.succeeded()
	if err := e.applyList(l, adopting, now); err != nil {
		e.status.LastError = err.Error()
		return e.backoff(now, 0, err.Error())
	}
	e.listNow = false
	e.nextList = now.Add(e.cfg.ListEvery)
	e.status.LastSync = now
	if len(e.refused) > 0 {
		e.status.LastResult = ResultRefused
	} else {
		e.status.LastResult, e.status.LastError = ResultOK, ""
	}
	return 0
}

func (e *Engine) applyList(l listAnswer, adopting bool, now time.Time) error {
	auth := e.cfg.Carrier.Authenticated()
	pre := e.cfg.Store.State()
	importedAccount := pre.Import != nil && pre.Account != nil && pre.Import.ServerID == pre.Account.ServerID
	byLocal := map[string]ServerApp{}
	byID := map[string]ServerApp{}
	for _, a := range l.Apps {
		if a.LocalID != "" {
			byLocal[a.LocalID] = a
		}
		byID[a.ID] = a
	}
	tomb := map[string]bool{}
	for _, d := range l.Deleted {
		tomb[d] = true
	}
	deleted := map[string]bool{}
	for _, id := range e.box.Deleted {
		deleted[id] = true
	}
	relinks := e.relinks
	e.relinks = nil
	removed := []string{}
	var notices []string
	adoptName := map[string]string{}
	skip := map[string]bool{}
	changed := false
	err := e.cfg.Store.Update(func(s *store.State) error {
		used := map[string]bool{}
		for _, t := range s.Targets {
			used[t.LocalID] = true
		}
		for _, r := range relinks {
			i := slices.IndexFunc(s.Targets, func(t store.Target) bool { return t.LocalID == r.localID && t.Name == r.name })
			var match *ServerApp
			for _, a := range l.Apps {
				if a.Name == r.name && a.LocalID != "" && a.LocalID != r.localID {
					match = &a
					break
				}
			}
			if i < 0 || match == nil || used[match.LocalID] || deleted[match.LocalID] || tomb[match.LocalID] {
				e.refused[r.localID] = refusal{reason: "name_taken", until: now.Add(e.cfg.ListEvery)}
				continue
			}
			e.log.Info("app relinked to its server local_id", "local_id", match.LocalID, "was", r.localID)
			s.Targets[i].LocalID = match.LocalID
			used[match.LocalID], used[r.localID] = true, false
			delete(e.refused, r.localID)
			changed = true
		}
		s.Targets = slices.DeleteFunc(s.Targets, func(t store.Target) bool {
			if !tomb[t.LocalID] {
				return false
			}
			if !auth {
				notices = append(notices, "server_reports_deleted:"+t.LocalID)
				return false
			}
			removed = append(removed, t.LocalID)
			return true
		})
		for i := range s.Targets {
			t := &s.Targets[i]
			a, ok := byLocal[t.LocalID]
			if !ok {
				if !adopting || t.ServerServiceID == "" || tomb[t.LocalID] || !importedAccount ||
					(t.Source != store.SourceV1Machine && t.Source != store.SourceV1FRPC) {
					continue
				}
				v1, listed := byID[t.ServerServiceID]
				switch {
				case !listed && auth:
					// Deleted on the website while this machine ran 1.x:
					// disabled here as 1.x did, never registered again.
					e.log.Info("app removed from the account before the first v2 sync; disabled here", "local_id", t.LocalID)
					t.Disabled, t.ServerServiceID, t.Subdomain = true, "", ""
					changed = true
				case !listed:
					skip[t.LocalID] = true
					notices = append(notices, "server_lists_without:"+t.LocalID)
				case v1.LocalID == "" && v1.Name != t.Name && checkApp(v1.Name, t.Host, t.Port, t.IconURL) == nil:
					adoptName[t.LocalID] = v1.Name
				}
				continue
			}
			if t.ServerServiceID != a.ID {
				t.ServerServiceID = a.ID
				changed = true
			}
			if t.Subdomain == "" {
				t.Subdomain = a.Subdomain
				changed = true
			}
			if t.ServerPublic != a.PublicRequested {
				t.ServerPublic = a.PublicRequested
				changed = true
			}
		}
		if !changed && len(removed) == 0 {
			return errUnchanged
		}
		return nil
	})
	if err := persisted(err); err != nil {
		return fmt.Errorf("record app list: %w", err)
	}
	e.changed = e.changed || changed || len(removed) > 0
	for _, id := range removed {
		e.log.Info("app deleted on the server; removed here", "local_id", id)
	}
	if auth {
		for _, d := range l.Deleted {
			if slices.Contains(removed, d) || slices.Contains(e.box.Registered, d) {
				e.box.Deleted = addID(e.box.Deleted, d, maxDeleted)
			}
			e.box.Registered = removeID(e.box.Registered, d)
			deleted[d] = true
		}
	}

	st := e.cfg.Store.State()
	local := map[string]bool{}
	for _, t := range st.Targets {
		local[t.LocalID] = true
		if _, ok := byLocal[t.LocalID]; ok {
			e.box.Registered = addID(e.box.Registered, t.LocalID, maxRegistered)
		}
	}
	for id := range e.refused {
		if !local[id] && !e.isRetired(id) {
			delete(e.refused, id)
			delete(e.split, id)
		}
	}

	var items []RegisterItem
	for _, t := range st.Targets {
		if t.Disabled || t.ServerDisableRequestedAt != nil || deleted[t.LocalID] || skip[t.LocalID] || tomb[t.LocalID] {
			continue
		}
		if err := checkApp(t.Name, t.Host, t.Port, t.IconURL); err != nil {
			e.refused[t.LocalID] = refusal{reason: err.Error()}
			continue
		}
		if r, ok := e.refused[t.LocalID]; ok && now.Before(r.until) {
			continue
		}
		if a, ok := byLocal[t.LocalID]; ok && !adopting && a.Name == t.Name && a.Host == t.Host && a.Port == t.Port {
			continue
		}
		name := t.Name
		if n, ok := adoptName[t.LocalID]; ok {
			name = n
		}
		items = append(items, RegisterItem{LocalID: t.LocalID, Name: name, Host: t.Host, Port: t.Port, IconURL: t.IconURL, PublicLocal: true})
	}
	// 1.x apps removed here before the first sync: adopted, then deleted by
	// their queued delete. After a refused adoption they are retried alone,
	// each register followed by its own delete, which is sent only once the
	// register confirmed the link.
	var retry []RegisterItem
	e.box.Retired = slices.DeleteFunc(e.box.Retired, func(r Retired) bool {
		v1, ok := byID[r.ServerID]
		if !ok || v1.LocalID != "" || checkApp(v1.Name, r.Host, r.Port, r.IconURL) != nil {
			// Gone or linked: nothing of ours left to adopt.
			delete(e.refused, r.LocalID)
			return true
		}
		it := RegisterItem{LocalID: r.LocalID, Name: v1.Name, Host: r.Host, Port: r.Port, IconURL: r.IconURL, PublicLocal: true}
		switch {
		case adopting:
			items = append(items, it)
		case !now.Before(e.refused[r.LocalID].until):
			retry = append(retry, it)
		}
		return false
	})
	var dels []string
	unlinked := []Unlinked{}
	unknown := 0
	for _, a := range l.Apps {
		switch {
		case a.LocalID == "":
			unlinked = append(unlinked, Unlinked{ID: a.ID, Name: a.Name})
		case deleted[a.LocalID]:
			dels = append(dels, a.LocalID)
			e.box.Registered = addID(e.box.Registered, a.LocalID, maxRegistered)
		case !local[a.LocalID]:
			unknown++
		}
	}
	if adopting {
		unlinked = nil
	}
	e.status.Unlinked, e.status.UnknownOnServer = unlinked, unknown
	e.status.Notices = notices
	if adopting && len(skip) > 0 {
		return errors.New("first sync waits for an authenticated app list")
	}

	calls, err := e.registerCalls(items, adopting, now)
	if err != nil {
		return err
	}
	for _, it := range retry {
		rc, err := registerCall([]RegisterItem{it}, false, now)
		if err != nil {
			return err
		}
		dc, err := deleteCall([]string{it.LocalID}, now)
		if err != nil {
			return err
		}
		calls = append(calls, rc, dc)
	}
	for i := 0; i < len(dels); i += MaxItems {
		c, err := deleteCall(dels[i:min(i+MaxItems, len(dels))], now)
		if err != nil {
			return err
		}
		calls = append(calls, c)
	}
	if len(e.box.Calls)+len(calls) > MaxCalls {
		calls = calls[:max(0, MaxCalls-len(e.box.Calls))]
		e.log.Warn("outbox full; remaining changes wait for the next sync")
	}
	if adopting {
		e.box.Calls = append(calls, e.box.Calls...)
		if len(calls) == 0 {
			e.markAdopted()
		}
	} else {
		e.box.Calls = append(e.box.Calls, calls...)
	}
	return e.save()
}

// registerCalls batches items into calls of at most MaxItems apps and
// MaxBody bytes; apps of a refused batch go one per call.
func (e *Engine) registerCalls(items []RegisterItem, adopt bool, now time.Time) ([]Call, error) {
	var calls []Call
	var cur []RegisterItem
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		c, err := registerCall(cur, adopt, now)
		if err != nil {
			return err
		}
		calls = append(calls, c)
		cur = nil
		return nil
	}
	for _, it := range items {
		if e.split[it.LocalID] {
			c, err := registerCall([]RegisterItem{it}, adopt, now)
			if err != nil {
				return nil, err
			}
			calls = append(calls, c)
			continue
		}
		next := append(slices.Clone(cur), it)
		b, _ := json.Marshal(registerBody{Apps: next})
		if len(next) > MaxItems || len(b) > MaxBody {
			if err := flush(); err != nil {
				return nil, err
			}
			next = []RegisterItem{it}
		}
		cur = next
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return calls, nil
}

func registerCall(items []RegisterItem, adopt bool, now time.Time) (Call, error) {
	body, err := json.Marshal(registerBody{Apps: items})
	if err != nil {
		return Call{}, err
	}
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.LocalID
	}
	return Call{Key: newKey(), Op: OpRegister, Body: body, LocalIDs: ids, Adopt: adopt, CreatedAt: now.UTC()}, nil
}

func deleteCall(ids []string, now time.Time) (Call, error) {
	body, err := json.Marshal(deleteBody{LocalIDs: ids})
	if err != nil {
		return Call{}, err
	}
	return Call{Key: newKey(), Op: OpDelete, Body: body, LocalIDs: slices.Clone(ids), CreatedAt: now.UTC()}, nil
}

// SetHealth replaces the pending health report; only the latest is sent.
func (e *Engine) SetHealth(statuses map[string]string) {
	e.mu.Lock()
	e.health = make(map[string]string, len(statuses))
	for id, s := range statuses {
		e.health[id] = s
	}
	e.healthGen++
	e.mu.Unlock()
	e.wake()
}

func (e *Engine) sendHealth(ctx context.Context, now time.Time) time.Duration {
	e.mu.Lock()
	gen := e.healthGen
	var items []healthItem
	for id, s := range e.health {
		if (s == "online" || s == "offline") && slices.Contains(e.box.Registered, id) {
			items = append(items, healthItem{LocalID: id, Status: s})
		}
	}
	e.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].LocalID < items[j].LocalID })
	for i := 0; i < len(items); i += MaxItems {
		body, _ := json.Marshal(healthBody{Apps: items[i:min(i+MaxItems, len(items))]})
		resp, err := e.call(ctx, Request{Method: pb.DeviceMethod_REPORT_HEALTH, Body: body})
		if err != nil || transientStatus(resp.Status) || resp.Status == http.StatusUnauthorized {
			e.mu.Lock()
			why := "health: outcome unknown"
			if err == nil {
				why = fmt.Sprintf("health: status %d", resp.Status)
			}
			d := e.backoff(now, resp.RetryAfter, why)
			e.mu.Unlock()
			return d
		}
		if resp.Status != http.StatusOK {
			e.log.Info("health report refused", "status", resp.Status, "reason", parseError(resp.Body).Error)
			break
		}
	}
	e.mu.Lock()
	e.succeeded()
	e.healthSent = gen
	e.mu.Unlock()
	return 0
}

// Add creates a local app with a new local_id; the next sync registers it.
func (e *Engine) Add(name, host string, port int) (string, error) {
	if err := checkApp(name, host, port, ""); err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidApp, err)
	}
	id := NewLocalID()
	err := e.cfg.Store.Update(func(s *store.State) error {
		if len(s.Targets) >= store.MaxTargets {
			return ErrTooManyApps
		}
		for _, t := range s.Targets {
			if strings.EqualFold(t.Name, name) {
				return ErrNameExists
			}
		}
		s.Targets = append(s.Targets, store.Target{LocalID: id, Name: name, Host: host, Port: port, Source: store.SourceLocal})
		return nil
	})
	if err := persisted(err); err != nil {
		return "", err
	}
	e.Kick()
	return id, nil
}

// Remove deletes a local app. The delete intent is written before the app
// is removed, so a crash in between still finishes the delete.
func (e *Engine) Remove(localID string) error {
	e.mu.Lock()
	defer e.wake()
	defer e.mu.Unlock()
	st := e.cfg.Store.State()
	if !slices.ContainsFunc(st.Targets, func(t store.Target) bool { return t.LocalID == localID }) {
		return ErrNoSuchApp
	}
	if st.Account != nil && ValidLocalID(st.Account.ServerID) {
		if err := e.bindServer(st.Account.ServerID); err != nil {
			return err
		}
	}
	renamed, err := e.prepare()
	if err != nil {
		return err
	}
	if id, ok := renamed[localID]; ok {
		localID = id
	}
	i := slices.IndexFunc(e.cfg.Store.State().Targets, func(t store.Target) bool { return t.LocalID == localID })
	if i < 0 {
		return nil
	}
	t := e.cfg.Store.State().Targets[i]
	before := cloneFile(e.box)
	queued := slices.ContainsFunc(e.box.Calls, func(c Call) bool { return c.Op == OpRegister && slices.Contains(c.LocalIDs, localID) })
	retire := !e.box.Adopted && !queued && ValidLocalID(t.ServerServiceID) && checkApp(t.Name, t.Host, t.Port, t.IconURL) == nil
	if slices.Contains(e.box.Registered, localID) || queued || retire {
		if err := e.queueDelete(localID, retire); err != nil {
			return err
		}
	}
	if retire {
		e.box.Retired = append(e.box.Retired, Retired{LocalID: localID, ServerID: t.ServerServiceID, Name: t.Name, Host: t.Host, Port: t.Port, IconURL: t.IconURL})
	}
	e.box.Deleted = addID(e.box.Deleted, localID, maxDeleted)
	if err := e.save(); err != nil {
		e.box = before
		return err
	}
	delete(e.refused, localID)
	delete(e.split, localID)
	if e.failRemoveTarget {
		return errors.New("injected failure")
	}
	err = e.cfg.Store.Update(func(s *store.State) error {
		s.Targets = slices.DeleteFunc(s.Targets, func(t store.Target) bool { return t.LocalID == localID })
		return nil
	})
	if err := persisted(err); err != nil {
		return err
	}
	e.changed = true
	return nil
}

// queueDelete adds a delete of localID; calls after the head were never
// sent, so the last one may grow. The delete of a retired app goes alone,
// so it is sent only if that app's adoption was confirmed.
func (e *Engine) queueDelete(localID string, alone bool) error {
	n := len(e.box.Calls)
	if !alone && n > 1 && e.box.Calls[n-1].Op == OpDelete && len(e.box.Calls[n-1].LocalIDs) < MaxItems &&
		!slices.ContainsFunc(e.box.Calls[n-1].LocalIDs, e.isRetired) {
		c, err := deleteCall(append(slices.Clone(e.box.Calls[n-1].LocalIDs), localID), e.cfg.Now())
		if err != nil {
			return err
		}
		c.Key = e.box.Calls[n-1].Key
		e.box.Calls[n-1] = c
		return nil
	}
	if n >= MaxCalls {
		return ErrOutboxFull
	}
	c, err := deleteCall([]string{localID}, e.cfg.Now())
	if err != nil {
		return err
	}
	e.box.Calls = append(e.box.Calls, c)
	return nil
}

func cloneFile(f File) File {
	out := f
	out.Calls = slices.Clone(f.Calls)
	for i := range out.Calls {
		out.Calls[i].Body = slices.Clone(f.Calls[i].Body)
		out.Calls[i].LocalIDs = slices.Clone(f.Calls[i].LocalIDs)
	}
	out.Registered = slices.Clone(f.Registered)
	out.Deleted = slices.Clone(f.Deleted)
	out.Retired = slices.Clone(f.Retired)
	return out
}
