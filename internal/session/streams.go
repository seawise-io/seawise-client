package session

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/visitor"
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

// TimeFloorFile keeps the time floor, for the next start.
const TimeFloorFile = "time-floor.json"

// ClockJump is how far the wall clock may move against the monotonic
// clock (suspend, a clock step) before signed time is asked for again.
const ClockJump = time.Minute

// floorStep is how far the floor must advance before it is written again.
const floorStep = 60

// ClockWrong is how far the system clock may be from signed time before
// it disagrees; it equals the visitor-token leeway.
const ClockWrong = visitor.Leeway * time.Second

const clockWrongSec = int64(ClockWrong / time.Second)

// plausibleMargin is how long before its source date a build may run.
const plausibleMargin = 30 * 24 * time.Hour

// fallbackPlausible applies to builds that carry no source date.
var fallbackPlausible = time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)

// MinPlausible is the earliest time this build can run at: its source date
// less plausibleMargin. A system clock below it has no real-time clock.
var MinPlausible = minPlausible(constants.BuildEpoch, vcsTime())

func minPlausible(epoch string, vcs time.Time) time.Time {
	if n, err := strconv.ParseInt(epoch, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0).UTC().Add(-plausibleMargin)
	}
	if !vcs.IsZero() {
		return vcs.UTC().Add(-plausibleMargin)
	}
	return fallbackPlausible
}

func vcsTime() time.Time {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return time.Time{}
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.time" {
			t, _ := time.Parse(time.RFC3339, s.Value)
			return t
		}
	}
	return time.Time{}
}

func plausible(w time.Time) bool { return !w.Before(MinPlausible) }

func near(a, b int64) bool { return a-b <= clockWrongSec && b-a <= clockWrongSec }

// floorFile holds the floor and the corroborated floor: the highest
// signed time that agreed with a plausible system clock.
type floorFile struct {
	Schema       int   `json:"schema"`
	Floor        int64 `json:"floor"`
	Corroborated int64 `json:"corroborated_floor,omitempty"`
}

// SignedClock keeps two clocks from control-key signed time.
//
// Now follows verified signed time (the source time plus the monotonic
// time since) and never goes below the time floor. A signed time replaces
// the source when it agrees with a plausible system clock, is trusted
// while the source is not, is closer to a plausible system clock than Now
// by more than ClockWrong, or is newer than the source and moves Now back
// by at most ClockWrong. Once trusted time arrived in this run, Now stays
// within ClockWrong of the highest trusted progression.
//
// A signed time is trusted when it agrees with a plausible system clock,
// or, with an implausible one, is at least MinPlausible and either at most
// ClockWrong below the floor or at least the corroborated floor while the
// floor is above it. Trusted time raises the floor; time that agrees with
// a plausible system clock, or with an implausible one lies far below an
// uncorroborated floor, may lower it, never below the corroborated floor,
// which only rises.
type SignedClock struct {
	wall      func() time.Time
	mono      func() time.Duration
	path      string
	log       *slog.Logger
	want      chan struct{}
	mu        sync.Mutex
	floor     int64
	corrFloor int64
	saved     int64
	savedCorr int64
	// Now's source.
	signed   int64
	at       time.Duration
	atWall   time.Time
	set      bool
	stale    bool
	srcTrust bool
	// The last trusted time, for TrustTime; cleared by a clock jump.
	trusted   int64
	trustedAt time.Duration
	tset      bool
	// The highest trusted progression in this run, bounding Now.
	low   int64
	lowAt time.Duration
	lset  bool
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
	if err == nil && (f.Schema != 1 || f.Floor <= 0 || f.Corroborated < 0) {
		err = errors.New("invalid")
	}
	if err != nil {
		log.Warn("stored time floor ignored", "error", err)
		return c
	}
	c.floor, c.corrFloor = max(f.Floor, f.Corroborated), f.Corroborated
	c.saved, c.savedCorr = c.floor, c.corrFloor
	return c
}

// source is Now's source time at mono m, or false before any.
func (c *SignedClock) source(m time.Duration) (int64, bool) {
	if !c.set || c.stale {
		return 0, false
	}
	return c.signed + int64(max(m-c.at, 0)/time.Second), true
}

// Observe takes a verified signed time in unix seconds.
func (c *SignedClock) Observe(t int64) {
	if t <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	w, m := c.wall(), c.mono()
	c.check(w)
	wu := w.Unix()
	agrees := plausible(w) && near(wu, t)
	rtcLess := !plausible(w) && t >= MinPlausible.Unix()
	// Without a real-time clock, a time far below an uncorroborated floor
	// may bring it down to the corroborated floor: it undoes a bad future
	// time that no plausible clock confirmed.
	lowers := rtcLess && c.floor > c.corrFloor && t >= c.corrFloor && t < c.floor-clockWrongSec
	trusted := agrees || lowers || (rtcLess && t >= c.floor-clockWrongSec)
	if cur, ok := c.source(m); ok {
		closer := plausible(w) && abs(wu-t)+clockWrongSec < abs(wu-cur)
		newer := t > c.signed && t >= cur-clockWrongSec
		if !(agrees || lowers || (trusted && !c.srcTrust) || closer || newer) {
			c.log.Warn("signed time older than the clock; ignored", "clock", cur, "signed", t)
			return
		}
	}
	c.signed, c.at, c.atWall, c.set, c.stale, c.srcTrust = t, m, w, true, false, trusted
	if !trusted {
		c.log.Warn("signed time not trusted", "system", wu, "signed", t, "floor", c.floor)
		return
	}
	c.trusted, c.trustedAt, c.tset = t, m, true
	if lowers || !c.lset || t > c.low+int64(max(m-c.lowAt, 0)/time.Second) {
		c.low, c.lowAt, c.lset = t, m, true
	}
	switch {
	case t >= c.floor:
		c.floor = t
	case (agrees || lowers) && c.floor > c.corrFloor:
		c.log.Warn("stored time floor is ahead of signed time; reset", "floor", c.floor, "signed", t)
		c.floor = max(t, c.corrFloor)
	}
	if agrees {
		c.corrFloor = max(c.corrFloor, t)
	}
	c.persist()
}

// persist writes the floors when they moved enough.
func (c *SignedClock) persist() {
	if c.path == "" {
		return
	}
	moved := func(now, saved int64) bool { return now < saved || now-saved >= floorStep || (saved == 0 && now > 0) }
	if !moved(c.floor, c.saved) && !moved(c.corrFloor, c.savedCorr) {
		return
	}
	b, _ := json.Marshal(floorFile{Schema: 1, Floor: c.floor, Corroborated: c.corrFloor})
	if err := store.WriteFileAtomic(c.path, b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		c.log.Warn("time floor not saved", "error", err)
		return
	}
	c.saved, c.savedCorr = c.floor, c.corrFloor
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// TrustTime is the time certificates and update metadata are checked at:
// a plausible system clock unless trusted signed time disagrees with it,
// else the trusted signed clock; without trusted time an implausible
// system clock is raised to the floor. Every result is at least the
// corroborated floor.
func (c *SignedClock) TrustTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.wall()
	c.check(w)
	t := w
	switch {
	case c.tset:
		corrected := time.Unix(c.trusted, 0).Add(max(c.mono()-c.trustedAt, 0))
		if !plausible(w) || !near(w.Unix(), corrected.Unix()) {
			t = corrected
		}
	case !plausible(w):
		t = later(w, time.Unix(c.floor, 0))
	}
	return later(t, time.Unix(c.corrFloor, 0))
}

// RetryTime is the time for one more certificate check after one failed
// as expired at TrustTime. It exists only while TrustTime rests on a floor
// no plausible clock corroborated, and is the corroborated floor, or the
// system clock without one.
func (c *SignedClock) RetryTime() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.wall()
	c.check(w)
	if c.tset || plausible(w) || c.floor <= c.corrFloor || !time.Unix(c.floor, 0).After(w) {
		return time.Time{}, false
	}
	return later(w, time.Unix(c.corrFloor, 0)), true
}

// check marks the clock stale when the wall clock moved more than
// ClockJump against the monotonic clock since the last signed time.
func (c *SignedClock) check(wall time.Time) {
	if !c.set || c.stale {
		return
	}
	d := wall.Sub(c.atWall) - (c.mono() - c.at)
	if d > ClockJump || d < -ClockJump {
		c.stale, c.tset = true, false
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
	if c.lset {
		t = later(t, time.Unix(c.low, 0).Add(max(c.mono()-c.lowAt, 0)-ClockWrong))
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

// Clock states shown in the UI.
const (
	ClockSigned   = "signed"
	ClockUnsigned = "unsigned"
	ClockIsWrong  = "wrong"
)

// ClockStatus is the clock as the local UI shows it. Offset is the system
// clock minus the corrected clock, in seconds, while signed time corrects
// the clock.
type ClockStatus struct {
	State  string `json:"state"`
	Floor  int64  `json:"floor,omitempty"`
	Offset *int64 `json:"offset_seconds,omitempty"`
	Text   string `json:"text,omitempty"`
}

const (
	clockWrongText   = "The clock on this machine is wrong. Seawise.io corrects for it with signed time, but other software here may not."
	clockBehindText  = "The clock on this machine is behind the last time Seawise.io confirmed. Waiting for signed time to correct it."
	clockWaitingText = "The clock on this machine is not set. Waiting for signed time from Seawise.io."
)

// Status reports whether signed time corrects the clock and whether the
// system clock is wrong: more than ClockWrong from signed time, or, before
// signed time in this run, more than ClockWrong behind the floor or below
// MinPlausible with a floor. Below MinPlausible without a floor the clock
// is only waiting.
func (c *SignedClock) Status() ClockStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.wall()
	c.check(w)
	s := ClockStatus{State: ClockUnsigned, Floor: c.floor}
	switch {
	case c.set && !c.stale:
		corrected := time.Unix(c.signed, 0).Add(max(c.mono()-c.at, 0))
		off := int64(w.Sub(corrected) / time.Second)
		s.State, s.Offset = ClockSigned, &off
		if !near(off, 0) {
			s.State, s.Text = ClockIsWrong, clockWrongText
		}
	case c.floor > 0 && (!plausible(w) || time.Unix(c.floor, 0).Sub(w) > ClockWrong):
		s.State, s.Text = ClockIsWrong, clockBehindText
	case !plausible(w):
		s.Text = clockWaitingText
	}
	return s
}

// Floor is the floor, from this run or a stored one.
func (c *SignedClock) Floor() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.floor, c.floor > 0
}
