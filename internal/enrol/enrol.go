// Package enrol moves a server paired by a 1.x client to its device key:
// it makes the key, enrols it with the 1.x token, and after the first
// call the server accepts from the key confirms the switch, which retires
// the token. It never unpairs, deletes or downgrades: failures back off
// and refusals hold with a reason.
package enrol

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

const (
	backoffBase = 30 * time.Second
	backoffMax  = 30 * time.Minute
	holdRetry   = 6 * time.Hour
	idleCheck   = time.Minute
	// maxReenrols bounds enrolments of a key the server then does not know.
	maxReenrols = 3
)

// Status states.
const (
	StateNotNeeded = "not_needed"
	StateEnrolling = "enrolling"
	StateEnrolled  = "enrolled"
	StateSwitched  = "switched"
	StateHeld      = "held"
)

// reconnectText ends every hold that only the server side can clear.
const reconnectText = "This server needs to be connected again. See the server's page on Seawise.io."

var holdText = map[string]string{
	store.HoldInvalidToken:    "The server did not accept this server's 1.x token. " + reconnectText,
	store.HoldAlreadyEnrolled: "Another device key is already enrolled for this server, for example a copy of this data directory. " + reconnectText,
	store.HoldBadKey:          "The server refused this device key because it was registered before. " + reconnectText,
	store.HoldRepairRequired:  "The server asks for this server to be connected again. " + reconnectText,
	store.HoldInvalidRequest:  "The server refused the enrolment request.",
	store.HoldIdentity:        "The server named another server or key for this device key.",
	store.HoldKeyRevoked:      "This device key was revoked. " + reconnectText,
	store.HoldNotEnrolled:     "The server refused to finish the switch: this key was not enrolled from the 1.x token.",
	store.HoldSwitchRefused:   "The server refused to finish the switch.",
	store.HoldTokenUnusable:   "The stored 1.x token is not in the expected format. " + reconnectText,
	store.HoldServerID:        "The stored server id is not valid. " + reconnectText,
	store.HoldKeyLost:         "The enrolled device key is missing or was replaced. " + reconnectText,
	store.HoldKeyUnknown:      "The server enrolled this device key but then did not accept it, several times. " + reconnectText,
	store.HoldInsecureOrigin:  "The API address is not an https address; the 1.x token is only sent over verified TLS.",
}

// NeedsReconnect reports whether hold can be cleared only by pairing the
// server again.
func NeedsReconnect(hold string) bool {
	return strings.HasSuffix(holdText[hold], reconnectText)
}

// Config wires an Enroller.
type Config struct {
	Store *store.Store
	Keys  identity.Keystore
	// Origin returns the API origin of the paired account.
	Origin func() string
	// Caller signs and sends device calls; nil builds one from Client,
	// Version and Now.
	Caller  *devicecall.Caller
	Client  *http.Client
	Version string
	Now     func() time.Time
	Logger  *slog.Logger
	// OnChange runs after the key is enrolled and after the switch.
	OnChange func(context.Context)
	// Jitter returns a factor in [0.8, 1.2]; tests fix it.
	Jitter func() float64
	// Gate is shared with the 1.x calls; it is held for writing from
	// sending enroll until its outcome is stored. Nil for none.
	Gate *sync.RWMutex
}

// Status is the enrolment as shown on the local page.
type Status struct {
	State          string    `json:"state"`
	Phase          string    `json:"phase,omitempty"`
	Hold           string    `json:"hold,omitempty"`
	HoldText       string    `json:"hold_text,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	NextAttempt    time.Time `json:"next_attempt,omitzero"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
}

// Enroller runs the enrolment steps. Step and Run are used from one
// goroutine; Status may be read from any.
type Enroller struct {
	cfg  Config
	log  *slog.Logger
	call *devicecall.Caller

	failures int
	reenrols int
	probed   bool
	started  bool

	mu     sync.Mutex
	status Status
}

func New(cfg Config) (*Enroller, error) {
	if cfg.Store == nil || cfg.Keys == nil || cfg.Origin == nil {
		return nil, errors.New("enrol: store, keys and origin required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Jitter == nil {
		cfg.Jitter = func() float64 { return 0.8 + 0.4*rand.Float64() }
	}
	c := cfg.Caller
	if c == nil {
		var err error
		if c, err = devicecall.New(devicecall.Config{Client: cfg.Client, Version: cfg.Version, Now: cfg.Now}); err != nil {
			return nil, err
		}
	}
	e := &Enroller{cfg: cfg, log: cfg.Logger.With("component", "enrol"), call: c}
	e.status = e.view("", time.Time{})
	return e, nil
}

// Ready reports whether a tunnel session or app call may use the device
// key: no enrolment is needed, or the server has enrolled the key.
func Ready(st store.State, sec store.Secrets) bool {
	if !st.EnrolmentNeeded(sec) {
		return true
	}
	e := st.EnrolmentFor()
	return e != nil && e.Phase == store.PhaseEnrolled
}

// LegacyAllowed reports whether 1.x calls with the token may be sent:
// never for an account paired with the device key, only until the server
// has enrolled the device key, and not once the server refused the token.
func LegacyAllowed(st store.State) bool {
	if st.Account.Keyed() {
		return false
	}
	e := st.EnrolmentFor()
	return e == nil || (e.Phase == store.PhasePending && e.Hold != store.HoldInvalidToken)
}

func (e *Enroller) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

// Run steps until ctx ends.
func (e *Enroller) Run(ctx context.Context) error {
	for {
		d := e.Step(ctx)
		if d <= 0 {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Step makes one transition and returns how long to wait before the next;
// zero means at once.
func (e *Enroller) Step(ctx context.Context) time.Duration {
	firstStep := !e.started
	e.started = true
	st, sec := e.cfg.Store.State(), e.cfg.Store.Secrets()
	rec := st.EnrolmentFor()
	if !st.EnrolmentNeeded(sec) {
		if rec != nil && rec.Phase == store.PhaseSwitched && sec.FRPToken != "" {
			if err := persist(e.cfg.Store.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = ""; return nil })); err != nil {
				return e.fail("store: " + err.Error())
			}
			e.log.Info("1.x token removed from local state")
			return 0
		}
		e.setStatus("", time.Time{})
		return idleCheck
	}
	now := e.cfg.Now()
	if rec == nil {
		serverID := st.Account.ServerID
		err := e.update(func(st *store.State) {
			st.Enrolment = &store.Enrolment{ServerID: serverID, Phase: store.PhasePending, StartedAt: now.UTC()}
		})
		if err != nil {
			return e.fail("store: " + err.Error())
		}
		e.log.Info("enrolling this server to client v2")
		return 0
	}
	if rec.Hold != "" && !firstStep && rec.HoldAt != nil {
		heldAt := *rec.HoldAt
		if heldAt.After(now) {
			heldAt = now
		}
		if wait := heldAt.Add(holdRetry).Sub(now); wait > 0 {
			e.setStatus("", now.Add(wait))
			return wait
		}
	}
	origin, err := devicecall.CheckOrigin(e.cfg.Origin())
	if err != nil {
		return e.hold(store.HoldInsecureOrigin)
	}
	if !claims.ValidUUID(rec.ServerID) {
		return e.hold(store.HoldServerID)
	}
	switch rec.Phase {
	case store.PhasePending:
		return e.enrol(ctx, origin, rec, sec.FRPToken)
	case store.PhaseEnrolled:
		return e.confirm(ctx, origin, rec)
	}
	return idleCheck
}

func validToken(t string) bool {
	if len(t) != 64 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if c := t[i]; !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (e *Enroller) enrol(ctx context.Context, origin string, rec *store.Enrolment, token string) time.Duration {
	if !validToken(token) {
		return e.hold(store.HoldTokenUnusable)
	}
	key, err := e.cfg.Keys.Current()
	if errors.Is(err, identity.ErrNoKey) {
		key, err = e.cfg.Keys.Create()
		if err == nil {
			e.log.Info("device key created", "key", key)
		}
	}
	if err != nil {
		return e.fail("device key: " + err.Error())
	}
	if rec.KeyID != key.KeyID() {
		kid := key.KeyID()
		if err := e.update(func(st *store.State) { st.Enrolment.KeyID = kid }); err != nil {
			return e.fail("store: " + err.Error())
		}
		return 0
	}
	// OnChange runs after the gate is released.
	notify := false
	defer func() {
		if notify {
			e.changed(ctx)
		}
	}()
	if g := e.cfg.Gate; g != nil {
		g.Lock()
		defer g.Unlock()
	}
	a, err := e.do(ctx, key, origin, http.MethodPost, PathEnroll, serverIDBody(rec.ServerID), token)
	if err != nil {
		return e.fail(err.Error())
	}
	if a.Status != http.StatusOK {
		return e.outcome(classify(PathEnroll, a.Status, a.Body), a)
	}
	m, err := devicecall.StrictStrings(a.Body, []string{"result", "server_id", "device_id", "key_id"})
	if err != nil || m["result"] != "enrolled" || !claims.ValidUUID(m["device_id"]) {
		return e.fail("unexpected enrol answer")
	}
	if m["server_id"] != rec.ServerID || m["key_id"] != key.KeyID() {
		return e.hold(store.HoldIdentity)
	}
	now := e.cfg.Now().UTC()
	deviceID := m["device_id"]
	err = e.update(func(st *store.State) {
		en := st.Enrolment
		en.Phase, en.DeviceID, en.EnrolledAt, en.Hold, en.HoldAt = store.PhaseEnrolled, deviceID, &now, "", nil
	})
	if err != nil {
		return e.fail("store: " + err.Error())
	}
	if e.reenrols == 0 {
		e.failures = 0
	}
	e.probed = false
	e.log.Info("device key enrolled", "key", key, "device_id", deviceID)
	notify = true
	return 0
}

func (e *Enroller) confirm(ctx context.Context, origin string, rec *store.Enrolment) time.Duration {
	key, err := e.cfg.Keys.Current()
	if errors.Is(err, identity.ErrNoKey) || (err == nil && key.KeyID() != rec.KeyID) {
		return e.hold(store.HoldKeyLost)
	}
	if err != nil {
		return e.fail("device key: " + err.Error())
	}
	if !e.probed {
		a, err := e.do(ctx, key, origin, http.MethodGet, PathIdentity, nil, "")
		if err != nil {
			return e.fail(err.Error())
		}
		if a.Status != http.StatusOK {
			return e.outcome(classify(PathIdentity, a.Status, a.Body), a)
		}
		m, err := devicecall.StrictStrings(a.Body, []string{"server_id", "device_id", "key_id"})
		if err != nil {
			return e.fail("unexpected identity answer")
		}
		if m["server_id"] != rec.ServerID || m["key_id"] != rec.KeyID {
			return e.hold(store.HoldIdentity)
		}
		e.probed = true
		return 0
	}
	a, err := e.do(ctx, key, origin, http.MethodPost, PathConfirm, serverIDBody(rec.ServerID), "")
	if err != nil {
		return e.fail(err.Error())
	}
	if a.Status != http.StatusOK {
		return e.outcome(classify(PathConfirm, a.Status, a.Body), a)
	}
	m, err := devicecall.StrictStrings(a.Body, []string{"result"})
	if err != nil || m["result"] != "switched" {
		return e.fail("unexpected confirm answer")
	}
	now := e.cfg.Now().UTC()
	err = e.update(func(st *store.State) {
		en := st.Enrolment
		en.Phase, en.SwitchedAt, en.Hold, en.HoldAt = store.PhaseSwitched, &now, "", nil
	})
	if err != nil {
		return e.fail("store: " + err.Error())
	}
	e.failures, e.reenrols = 0, 0
	e.log.Info("switched to the device key; the 1.x token is retired", "key", key)
	e.changed(ctx)
	return 0
}

func (e *Enroller) outcome(o outcome, a devicecall.Answer) time.Duration {
	switch o.kind {
	case kindHold:
		return e.hold(o.hold)
	case kindUnknownKey:
		e.probed = false
		e.reenrols++
		err := e.update(func(st *store.State) {
			en := st.Enrolment
			en.Phase, en.DeviceID, en.EnrolledAt = store.PhasePending, "", nil
		})
		if err != nil {
			return e.fail("store: " + err.Error())
		}
		if e.reenrols >= maxReenrols {
			e.reenrols = 0
			return e.hold(store.HoldKeyUnknown)
		}
		e.log.Warn("server does not know the enrolled key; enrolling it again")
		return e.backoff("device key not known to the server", 0)
	}
	return e.backoff(o.reason, a.RetryAfter)
}

func (e *Enroller) hold(reason string) time.Duration {
	now := e.cfg.Now().UTC()
	err := e.update(func(st *store.State) { st.Enrolment.Hold, st.Enrolment.HoldAt = reason, &now })
	if err != nil {
		return e.fail("store: " + err.Error())
	}
	e.failures = 0
	e.log.Warn("enrolment on hold; nothing was removed", "reason", reason)
	e.setStatus("", now.Add(holdRetry))
	return holdRetry
}

func (e *Enroller) fail(msg string) time.Duration { return e.backoff(msg, 0) }

func (e *Enroller) backoff(msg string, floor time.Duration) time.Duration {
	e.failures++
	d := backoffBase << min(e.failures-1, 6)
	d = min(d, backoffMax)
	d = time.Duration(float64(d) * e.cfg.Jitter())
	d = max(d, floor)
	e.log.Warn("enrolment attempt failed; retrying", "error", msg, "in", d.Round(time.Second))
	e.setStatus(msg, e.cfg.Now().Add(d))
	return d
}

func (e *Enroller) changed(ctx context.Context) {
	e.setStatus("", time.Time{})
	if e.cfg.OnChange != nil {
		e.cfg.OnChange(ctx)
	}
}

// update changes the enrolment record of the paired server.
func (e *Enroller) update(fn func(*store.State)) error {
	return persist(e.cfg.Store.Update(func(st *store.State) error {
		if st.Account == nil {
			return errors.New("server is no longer paired")
		}
		if st.Enrolment == nil || st.Enrolment.ServerID != st.Account.ServerID {
			st.Enrolment = nil
		}
		fn(st)
		if st.Enrolment == nil {
			return errors.New("no enrolment record")
		}
		return nil
	}))
}

func persist(err error) error {
	if errors.Is(err, store.ErrNotDurable) {
		return nil
	}
	return err
}

func (e *Enroller) setStatus(lastErr string, next time.Time) {
	v := e.view(lastErr, next)
	e.mu.Lock()
	e.status = v
	e.mu.Unlock()
}

func (e *Enroller) view(lastErr string, next time.Time) Status {
	st, sec := e.cfg.Store.State(), e.cfg.Store.Secrets()
	rec := st.EnrolmentFor()
	s := Status{LastError: lastErr, NextAttempt: next}
	key, keyErr := e.cfg.Keys.Current()
	if keyErr == nil {
		s.KeyFingerprint = key.Fingerprint()
	} else if !errors.Is(keyErr, identity.ErrNoKey) && s.LastError == "" {
		s.LastError = "device key: " + keyErr.Error()
	}
	if rec != nil {
		s.Phase = rec.Phase
	}
	lost := errors.Is(keyErr, identity.ErrNoKey) || (keyErr == nil && rec != nil && key.KeyID() != rec.KeyID)
	switch {
	case rec != nil && rec.Phase == store.PhaseSwitched && lost:
		s.State, s.Hold, s.HoldText = StateHeld, store.HoldKeyLost, holdText[store.HoldKeyLost]
	case rec != nil && rec.Hold != "":
		s.State, s.Hold, s.HoldText = StateHeld, rec.Hold, holdText[rec.Hold]
	case rec != nil && rec.Phase == store.PhaseSwitched:
		s.State = StateSwitched
	case !st.EnrolmentNeeded(sec):
		s.State = StateNotNeeded
	case rec != nil && rec.Phase == store.PhaseEnrolled:
		s.State = StateEnrolled
	default:
		s.State = StateEnrolling
	}
	return s
}
