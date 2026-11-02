// Package pair pairs an unpaired agent with a SeaWise account through the
// device flow, bound to a device key made for this pairing: the request
// carries the new key's proof, and polling and completion must be signed
// by the same key. The account is stored with the device and key id the
// server returns; no 1.x token is involved.
package pair

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

// Pairing states.
const (
	StateIdle    = "none"
	StatePending = "pending"
	StatePaired  = "paired"
	StateFailed  = "failed"
)

const (
	defaultName  = "My Server"
	defaultPoll  = 5 * time.Second
	cancelWithin = 5 * time.Second
)

var (
	ErrPaired      = errors.New("this client is already paired")
	ErrInvalidName = errors.New("server name must be 1 to 100 characters without control characters")
)

// Error is a refusal or failure whose text may be shown as is.
type Error struct{ Text string }

func (e *Error) Error() string { return e.Text }

// Config wires a Pairer.
type Config struct {
	// Context ends polling when the agent stops.
	Context context.Context
	Store   *store.Store
	Keys    identity.Keystore
	Caller  *devicecall.Caller
	// Origin is the API origin to pair with; it must be https.
	Origin func() string
	// WebURL is the site where the owner approves the code.
	WebURL string
	Now    func() time.Time
	Poll   time.Duration
	Logger *slog.Logger
	// OnPaired runs after the account is stored.
	OnPaired func(context.Context)
}

// Status is the pairing as shown on the local page. It never carries the
// device code.
type Status struct {
	State          string    `json:"state"`
	Code           string    `json:"code,omitempty"`
	ApproveURL     string    `json:"approve_url,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	KeyFingerprint string    `json:"key_fingerprint,omitempty"`
	ServerName     string    `json:"server_name,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// attempt is one pairing code being polled.
type attempt struct {
	key    *identity.Key
	origin string
	codes  codes
	cancel context.CancelFunc
	done   chan struct{}
	// finished is set by the poller once the code needs no cancel.
	finished bool
}

type Pairer struct {
	cfg Config
	log *slog.Logger

	// op serialises Start and Cancel.
	op sync.Mutex

	mu     sync.Mutex
	cur    *attempt
	status Status
}

func New(cfg Config) (*Pairer, error) {
	if cfg.Store == nil || cfg.Keys == nil || cfg.Caller == nil || cfg.Origin == nil {
		return nil, errors.New("pair: store, keys, caller and origin required")
	}
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Poll <= 0 {
		cfg.Poll = defaultPoll
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Pairer{cfg: cfg, log: cfg.Logger.With("component", "pair"), status: Status{State: StateIdle}}, nil
}

// Status reports the pairing; a stored account shows as paired.
func (p *Pairer) Status() Status {
	if acc := p.cfg.Store.State().Account; acc != nil {
		return Status{State: StatePaired, ServerName: acc.ServerName}
	}
	p.mu.Lock()
	s := p.status
	p.mu.Unlock()
	if s.State == StatePaired {
		return Status{State: StateIdle}
	}
	return s
}

// Start asks for a pairing code with a new device key and polls for the
// owner's approval in the background. A pairing already running is
// cancelled first.
func (p *Pairer) Start(ctx context.Context, name string) (Status, error) {
	p.op.Lock()
	defer p.op.Unlock()
	p.stop()
	if p.cfg.Store.State().Account != nil {
		return Status{}, ErrPaired
	}
	name, err := cleanName(name)
	if err != nil {
		return Status{}, err
	}
	origin, err := devicecall.CheckOrigin(p.cfg.Origin())
	if err != nil {
		return p.failStart(&Error{Text: "The Seawise.io API address is not an https address."})
	}
	key, err := p.cfg.Keys.Replace()
	if err != nil {
		p.log.Error("device key for pairing", "error", err)
		return p.failStart(&Error{Text: "Could not create a device key: " + err.Error()})
	}
	p.log.Info("new device key for pairing", "key", key)
	body, _ := json.Marshal(map[string]string{"server_name": name})
	a, err := p.cfg.Caller.Do(ctx, key, origin, http.MethodPost, PathRequest, body, nil)
	if err != nil {
		p.log.Warn("pairing request failed", "error", err)
		return p.failStart(&Error{Text: "Could not reach Seawise.io. Check this machine's internet connection and try again."})
	}
	if a.Status != http.StatusOK {
		p.log.Warn("pairing request refused", "status", a.Status, "code", devicecall.SafeCode(devicecall.ParseRefusal(a.Body).Code))
		return p.failStart(requestError(a))
	}
	c, err := parseCodes(a.Body, p.cfg.Now())
	if err != nil {
		return p.failStart(&Error{Text: "Seawise.io sent an unexpected answer. Try again."})
	}
	if c.keyID != key.KeyID() {
		return p.failStart(&Error{Text: "Seawise.io bound another key to this request. Try again."})
	}
	run, cancel := context.WithCancel(p.cfg.Context)
	at := &attempt{key: key, origin: origin, codes: c, cancel: cancel, done: make(chan struct{})}
	s := Status{State: StatePending, Code: c.user, ApproveURL: approveURL(p.cfg.WebURL), ExpiresAt: c.expires, KeyFingerprint: key.Fingerprint()}
	p.mu.Lock()
	p.cur, p.status = at, s
	p.mu.Unlock()
	p.log.Info("pairing code issued; waiting for approval", "key", key, "expires_at", c.expires)
	go p.poll(run, at)
	return s, nil
}

// Cancel stops a running pairing and cancels its code at SeaWise.
func (p *Pairer) Cancel() {
	p.op.Lock()
	defer p.op.Unlock()
	p.stop()
	p.mu.Lock()
	if p.status.State != StatePaired {
		p.status = Status{State: StateIdle}
	}
	p.mu.Unlock()
}

// stop ends the current attempt and, if its code is still open, cancels
// it at SeaWise with the key that requested it. The caller holds op.
func (p *Pairer) stop() {
	p.mu.Lock()
	at := p.cur
	p.cur = nil
	p.mu.Unlock()
	if at == nil {
		return
	}
	at.cancel()
	<-at.done
	p.mu.Lock()
	open := !at.finished
	p.mu.Unlock()
	if !open {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(p.cfg.Context), cancelWithin)
	defer cancel()
	if _, err := p.cfg.Caller.Do(ctx, at.key, at.origin, http.MethodPost, PathCancel, deviceCodeBody(at.codes.device), nil); err != nil {
		p.log.Warn("pairing cancel not sent", "error", err)
		return
	}
	p.log.Info("pairing cancelled")
}

func (p *Pairer) failStart(err *Error) (Status, error) {
	p.mu.Lock()
	p.status = Status{State: StateFailed, Error: err.Text}
	p.mu.Unlock()
	return Status{}, err
}

func deviceCodeBody(code string) []byte {
	b, _ := json.Marshal(map[string]string{"device_code": code})
	return b
}

// approveURL is the page where the owner types the code; the code is
// never put in the link, so a link cannot approve a request.
func approveURL(web string) string {
	u, err := url.Parse(web)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/connect"}).String()
}

// poll checks the code until it is approved, refused or expired.
func (p *Pairer) poll(ctx context.Context, at *attempt) {
	defer close(at.done)
	defer at.cancel()
	wait := p.cfg.Poll
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if !p.cfg.Now().Before(at.codes.expires) {
			p.finish(at, StateFailed, "The pairing code expired. Start pairing again.")
			return
		}
		var done bool
		done, wait = p.check(ctx, at)
		if done {
			return
		}
	}
}

// check polls once and completes an approved code. It reports whether
// the attempt ended and how long to wait before the next poll.
func (p *Pairer) check(ctx context.Context, at *attempt) (bool, time.Duration) {
	a, err := p.cfg.Caller.Do(ctx, at.key, at.origin, http.MethodPost, PathStatus, deviceCodeBody(at.codes.device), nil)
	if err != nil {
		p.note(at, "Seawise.io unreachable; still waiting")
		return false, p.cfg.Poll
	}
	if a.Status != http.StatusOK {
		return p.transient(at, a)
	}
	m, err := fields(a.Body, []string{"status"}, "server_name")
	if err != nil {
		p.note(at, "unexpected answer from Seawise.io; still waiting")
		return false, p.cfg.Poll
	}
	switch m["status"] {
	case "pending":
		p.note(at, "")
		return false, p.cfg.Poll
	case "approved", "used":
		// A completion whose answer was lost shows as used; completing
		// again with the same key returns the same pairing.
		return p.complete(ctx, at)
	case "expired":
		p.finish(at, StateFailed, "The pairing code expired. Start pairing again.")
	case "cancelled":
		p.finish(at, StateFailed, "The pairing was cancelled. Start pairing again.")
	case "invalid":
		p.finish(at, StateFailed, "Seawise.io no longer knows this pairing code. Start pairing again.")
	default:
		p.note(at, "unexpected answer from Seawise.io; still waiting")
		return false, p.cfg.Poll
	}
	return true, 0
}

// transient handles a refused poll or completion: limits, outages and
// proof refusals are retried; anything else ends the attempt.
func (p *Pairer) transient(at *attempt, a devicecall.Answer) (bool, time.Duration) {
	if a.Status == http.StatusTooManyRequests {
		p.note(at, "rate limited by Seawise.io; still waiting")
		return false, max(p.cfg.Poll, a.RetryAfter)
	}
	if a.Status >= 500 || a.Status == http.StatusUnauthorized || a.Status == http.StatusNotFound {
		p.note(at, "Seawise.io answered "+strconv.Itoa(a.Status)+"; still waiting")
		return false, p.cfg.Poll
	}
	p.finish(at, StateFailed, "Seawise.io refused the pairing (status "+strconv.Itoa(a.Status)+"). Start pairing again.")
	return true, 0
}

func (p *Pairer) complete(ctx context.Context, at *attempt) (bool, time.Duration) {
	a, err := p.cfg.Caller.Do(ctx, at.key, at.origin, http.MethodPost, PathComplete, deviceCodeBody(at.codes.device), nil)
	if err != nil {
		p.note(at, "Seawise.io unreachable while finishing; retrying")
		return false, p.cfg.Poll
	}
	switch a.Status {
	case http.StatusOK:
	case http.StatusBadRequest:
		p.finish(at, StateFailed, "The pairing was not approved or the code expired. Start pairing again.")
		return true, 0
	case http.StatusForbidden:
		p.finish(at, StateFailed, "Your account has reached its server limit. Remove a server you no longer use, or upgrade, then start pairing again.")
		return true, 0
	default:
		return p.transient(at, a)
	}
	r, err := parsePairing(a.Body)
	if err != nil {
		p.note(at, "unexpected answer from Seawise.io while finishing; retrying")
		return false, p.cfg.Poll
	}
	if r.keyID != at.key.KeyID() {
		p.finish(at, StateFailed, "Seawise.io paired another key. Start pairing again.")
		return true, 0
	}
	if err := p.save(at, r); err != nil {
		if errors.Is(err, ErrPaired) {
			p.finish(at, StateFailed, "This client was paired another way meanwhile.")
			return true, 0
		}
		p.log.Error("store pairing", "error", err)
		p.note(at, "could not save the pairing: "+err.Error()+"; retrying")
		return false, p.cfg.Poll
	}
	p.log.Info("paired with the device key", "server_id", r.serverID, "device_id", r.deviceID, "key", at.key)
	p.finish(at, StatePaired, "")
	if p.cfg.OnPaired != nil {
		p.cfg.OnPaired(context.WithoutCancel(ctx))
	}
	return true, 0
}

// save stores the account. Apps keep their definitions but lose the
// registrations of any earlier server, so they register on this one; a
// 1.x token left from an earlier account is removed first.
func (p *Pairer) save(at *attempt, r pairing) error {
	if p.cfg.Store.State().Account != nil {
		return ErrPaired
	}
	if p.cfg.Store.Secrets().FRPToken != "" {
		if err := persist(p.cfg.Store.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = ""; return nil })); err != nil {
			return err
		}
	}
	return persist(p.cfg.Store.Update(func(st *store.State) error {
		if st.Account != nil {
			return ErrPaired
		}
		st.Account = &store.Account{
			ServerID: r.serverID, ServerName: r.serverName, APIURL: at.origin, UserID: r.userID,
			DeviceID: r.deviceID, KeyID: r.keyID,
		}
		st.Enrolment = nil
		for i := range st.Targets {
			t := &st.Targets[i]
			t.ServerServiceID, t.Subdomain, t.ServerPublic, t.ServerDisableRequestedAt = "", "", false, nil
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

// note records a passing problem on a pending attempt.
func (p *Pairer) note(at *attempt, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == at {
		p.status.Error = msg
	}
}

// finish ends at with state; the code needs no cancel afterwards.
func (p *Pairer) finish(at *attempt, state, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at.finished = true
	if p.cur != at {
		return
	}
	p.cur = nil
	if state == StatePaired {
		p.status = Status{State: StatePaired}
		return
	}
	p.status = Status{State: state, Error: msg}
	p.log.Warn("pairing ended", "reason", msg)
}
