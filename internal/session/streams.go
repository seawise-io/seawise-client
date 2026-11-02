package session

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/store"
)

// DataSession is what a data-stream handler needs from one session.
type DataSession struct {
	Mux          *yamux.Session
	Capabilities []string // negotiated in HelloAck
	MaxStreams   int      // HelloAck.max_streams
	EdgeID       string
	// Routes is the newest RouteSet applied on this session, or nil.
	Routes func() *claims.RouteSet
	// Ended carries apps whose streams must end: revoked, or dropped from
	// the session's RouteSet.
	Ended *AppEnds
}

// AppEnds is an unbounded queue of app ids; Push never blocks.
type AppEnds struct {
	mu      sync.Mutex
	pending []string
	ch      chan struct{}
}

// NewAppEnds returns an empty queue.
func NewAppEnds() *AppEnds { return &AppEnds{ch: make(chan struct{}, 1)} }

// Push queues app ids and signals C.
func (a *AppEnds) Push(ids ...string) {
	if a == nil || len(ids) == 0 {
		return
	}
	a.mu.Lock()
	a.pending = append(a.pending, ids...)
	a.mu.Unlock()
	select {
	case a.ch <- struct{}{}:
	default:
	}
}

// C is signalled after a Push.
func (a *AppEnds) C() <-chan struct{} { return a.ch }

// Take returns and clears the queued ids.
func (a *AppEnds) Take() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.pending
	a.pending = nil
	return out
}

// TimeFloorFile keeps the highest signed time seen, for the next start.
const TimeFloorFile = "time-floor.json"

// ClockJump is how far the wall clock may move against the monotonic
// clock (suspend, a clock step) before signed time is asked for again.
const ClockJump = time.Minute

// floorStep is how far the floor must advance before it is written again.
const floorStep = 60

// floorHeal: a signed time this far below the floor replaces it, so a bad
// stored floor cannot hold the clock in the future.
const floorHeal = 3600

type floorFile struct {
	Schema int   `json:"schema"`
	Floor  int64 `json:"floor"`
}

// SignedClock is the agent clock corrected by control-key signed time: the
// last signed time plus the monotonic time since it was observed. Before
// any signed time in this run, or after the wall clock jumped, it is not
// Ready and gives the later of the corrected time and the wall clock; it
// never goes below the highest signed time seen, persisted across starts.
type SignedClock struct {
	wall   func() time.Time
	mono   func() time.Duration
	path   string
	log    *slog.Logger
	want   chan struct{}
	mu     sync.Mutex
	floor  int64
	saved  int64
	signed int64
	at     time.Duration
	atWall time.Time
	set    bool
	stale  bool
}

// NewSignedClock returns an in-memory clock over now; nil uses the system
// clock with its monotonic reading. A given now also serves as the
// monotonic clock.
func NewSignedClock(now func() time.Time) *SignedClock {
	if now == nil {
		return openSignedClock("", nil, nil, nil)
	}
	epoch := now()
	return openSignedClock("", now, func() time.Duration { return now().Sub(epoch) }, nil)
}

// OpenSignedClock returns a system clock whose floor is kept in dir.
func OpenSignedClock(dir string, log *slog.Logger) *SignedClock {
	return openSignedClock(dir, nil, nil, log)
}

func openSignedClock(dir string, wall func() time.Time, mono func() time.Duration, log *slog.Logger) *SignedClock {
	if wall == nil || mono == nil {
		base := time.Now()
		wall, mono = time.Now, func() time.Duration { return time.Since(base) }
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &SignedClock{wall: wall, mono: mono, log: log, want: make(chan struct{}, 1)}
	if dir == "" {
		return c
	}
	c.path = filepath.Join(dir, TimeFloorFile)
	b, err := store.ReadOwned(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return c
	}
	var f floorFile
	if err == nil {
		err = json.Unmarshal(b, &f)
	}
	if err == nil && (f.Schema != 1 || f.Floor <= 0) {
		err = errors.New("invalid")
	}
	if err != nil {
		log.Warn("stored time floor ignored", "error", err)
		return c
	}
	c.floor, c.saved = f.Floor, f.Floor
	return c
}

// Observe takes a verified signed time in unix seconds; one not above the
// highest observed in this run is ignored.
func (c *SignedClock) Observe(t int64) {
	if t <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set && t <= c.signed {
		return
	}
	c.signed, c.at, c.atWall, c.set, c.stale = t, c.mono(), c.wall(), true, false
	heal := c.floor-t > floorHeal
	if heal {
		c.log.Warn("stored time floor is far ahead of signed time; reset", "floor", c.floor, "signed", t)
		c.floor = t
	}
	c.floor = max(c.floor, t)
	if c.path != "" && (heal || c.saved == 0 || c.floor-c.saved >= floorStep) {
		b, _ := json.Marshal(floorFile{Schema: 1, Floor: c.floor})
		if err := store.WriteFileAtomic(c.path, b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
			c.log.Warn("time floor not saved", "error", err)
			return
		}
		c.saved = c.floor
	}
}

// check marks the clock stale when the wall clock moved more than
// ClockJump against the monotonic clock since the last signed time.
func (c *SignedClock) check(wall time.Time) {
	if !c.set || c.stale {
		return
	}
	d := wall.Sub(c.atWall) - (c.mono() - c.at)
	if d > ClockJump || d < -ClockJump {
		c.stale = true
		c.log.Warn("system clock jumped; asking for signed time")
		select {
		case c.want <- struct{}{}:
		default:
		}
	}
}

// Now is the corrected time, never below the floor.
func (c *SignedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.wall()
	floor := time.Unix(c.floor, 0)
	if !c.set {
		return later(w, floor)
	}
	c.check(w)
	t := time.Unix(c.signed, 0).Add(max(c.mono()-c.at, 0))
	if c.stale {
		t = later(t, w)
	}
	return later(t, floor)
}

// Ready reports whether signed time corrects the clock in this run.
func (c *SignedClock) Ready() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.check(c.wall())
	return c.set && !c.stale
}

// Wanted is signalled when the clock needs signed time again.
func (c *SignedClock) Wanted() <-chan struct{} { return c.want }

// Floor is the highest signed time known, from this run or a stored one.
func (c *SignedClock) Floor() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.floor, c.floor > 0
}
