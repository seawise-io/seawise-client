package visitor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

// Mode is how the gate acts on its decisions.
type Mode string

const (
	// Observe allows every request and records what enforce would refuse.
	Observe Mode = "observe"
	// Enforce refuses a request without a valid token for the app.
	Enforce Mode = "enforce"
)

// Decision codes besides the token refusal reasons. A stale-ok refusal is
// "stale_" followed by its reason.
const (
	CodeValid    = "valid"
	CodePublic   = "public"
	CodeStaleOk  = "stale_ok"
	CodeMissing  = "missing"
	CodeNoKeySet = "no_key_set"
	CodeWrongApp = "wrong_app"
	// CodeStaleIneligible: the edge never serves stale for share sessions
	// or for user tokens shorter than MinStaleLifetime.
	CodeStaleIneligible = "stale_ineligible"
	CodeExpired         = string(Expired)
	CodeNotYetValid     = string(NotYetValid)
)

// Leeway is the tolerance on a visitor token's times, in seconds.
const Leeway = 300

// MinStaleLifetime is the shortest user token (exp - iat) the edge serves
// stale.
const MinStaleLifetime = 900

const logEvery = time.Minute

// Config configures a Gate.
type Config struct {
	// KeySet is the current verified key set, or nil.
	KeySet func() *protocol.KeySet
	// Mode is the enforcement mode; nil or an unknown value is Observe.
	Mode func() Mode
	// Now is the agent's corrected clock. Required, as is KeySet.
	Now    func() time.Time
	Logger *slog.Logger
}

// Request is what a data stream asks for.
type Request struct {
	// AppID is the app the stream names (canonical uuid).
	AppID string
	// Public is set only for an app every source marks public.
	Public bool
	// Token and StaleOk are the stream header's visitor_token and
	// stale_ok_until.
	Token, StaleOk string
}

// Decision is the gate's answer. Code says why; Session is a short hash of
// the token's session id, never the token or a user id.
type Decision struct {
	Allow   bool
	Code    string
	Mode    Mode
	Kind    string
	Session string
}

// Valid reports whether the request passed the check, whatever the mode.
func (d Decision) Valid() bool {
	return d.Code == CodeValid || d.Code == CodePublic || d.Code == CodeStaleOk
}

// Reply is the data-stream reply code for the decision.
func (d Decision) Reply() pb.ReplyCode {
	if d.Allow {
		return pb.ReplyCode_ACCEPTED
	}
	return pb.ReplyCode_TOKEN_REJECTED
}

// Status is the mode and the number of decisions per code.
type Status struct {
	Mode   Mode              `json:"mode"`
	Counts map[string]uint64 `json:"counts"`
}

// Gate checks visitor tokens on data streams.
type Gate struct {
	cfg  Config
	log  *slog.Logger
	keys atomic.Pointer[Keys]

	mu      sync.Mutex
	counts  map[string]uint64
	lastLog map[string]time.Time
}

// New returns a gate.
func New(cfg Config) (*Gate, error) {
	if cfg.Now == nil || cfg.KeySet == nil {
		return nil, errors.New("visitor gate needs a clock and a key set")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Gate{cfg: cfg, log: cfg.Logger.With("component", "visitor"), counts: map[string]uint64{}, lastLog: map[string]time.Time{}}, nil
}

func (g *Gate) mode() Mode {
	if g.cfg.Mode != nil && g.cfg.Mode() == Enforce {
		return Enforce
	}
	return Observe
}

// currentKeys indexes the current key set once per set.
func (g *Gate) currentKeys() *Keys {
	ks := g.cfg.KeySet()
	if ks == nil {
		return nil
	}
	if k := g.keys.Load(); k != nil && k.set == ks {
		return k
	}
	k := NewKeys(ks)
	g.keys.Store(k)
	return k
}

// Check decides one request.
func (g *Gate) Check(r Request) Decision {
	now := g.cfg.Now()
	d := g.check(r, now.Unix())
	d.Mode = g.mode()
	d.Allow = d.Valid() || d.Mode == Observe
	if !d.Valid() {
		d.Kind, d.Session = "", ""
	}
	g.record(d, r.AppID, now)
	return d
}

func (g *Gate) check(r Request, now int64) Decision {
	if r.Public && r.Token == "" {
		return Decision{Code: CodePublic}
	}
	d := g.verify(r, now)
	if r.Public && d.Code != CodeValid {
		return Decision{Code: CodePublic}
	}
	return d
}

func (g *Gate) verify(r Request, now int64) Decision {
	keys := g.currentKeys()
	if keys == nil {
		return Decision{Code: CodeNoKeySet}
	}
	if r.Token == "" {
		return Decision{Code: CodeMissing}
	}
	t, err := VerifyToken(r.Token, keys)
	if err != nil {
		return Decision{Code: string(ReasonOf(err))}
	}
	if t.Aud != r.AppID {
		return Decision{Code: CodeWrongApp}
	}
	if t.Iat-Leeway > now {
		return Decision{Code: CodeNotYetValid}
	}
	ok := Decision{Code: CodeValid, Kind: t.Kind, Session: sessionRef(t.Sid)}
	if now <= t.Exp+Leeway {
		return ok
	}
	if r.StaleOk == "" {
		return Decision{Code: CodeExpired}
	}
	if t.Kind != "user" || t.Exp-t.Iat < MinStaleLifetime {
		return Decision{Code: CodeStaleIneligible}
	}
	if _, err := CheckStaleOk(r.StaleOk, t, keys, now); err != nil {
		return Decision{Code: "stale_" + string(ReasonOf(err))}
	}
	ok.Code = CodeStaleOk
	return ok
}

func sessionRef(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return "sid:" + hex.EncodeToString(sum[:6])
}

func (g *Gate) record(d Decision, app string, now time.Time) {
	g.mu.Lock()
	g.counts[d.Code]++
	logIt := false
	if !d.Valid() {
		if last, ok := g.lastLog[d.Code]; !ok || now.Sub(last) >= logEvery {
			g.lastLog[d.Code] = now
			logIt = true
		}
	}
	g.mu.Unlock()
	if !logIt {
		return
	}
	if !uuidRE.MatchString(app) {
		app = "invalid"
	}
	if d.Allow {
		g.log.Info("visitor token would be refused", "mode", d.Mode, "code", d.Code, "app", app)
	} else {
		g.log.Warn("visitor refused", "mode", d.Mode, "code", d.Code, "app", app)
	}
}

// Status returns the mode and a copy of the counters.
func (g *Gate) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	return Status{Mode: g.mode(), Counts: maps.Clone(g.counts)}
}
