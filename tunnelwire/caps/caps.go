// Package caps holds the seawise-tunnel/1 resource limits: the yamux
// configuration, stream caps derived from buffer budgets, the byte budgets
// themselves, liveness timing and session lifetime.
//
// Streams are multiplexed with libp2p/go-yamux. A stream starts with a
// 256 KiB receive window and grows it, doubling per round trip while the
// reader keeps up, to at most 16 MiB. Every reservation goes through a Gate
// that charges it to the session's byte budget (and at the edge to the
// global budget), so growth comes only from what idle streams leave unused.
package caps

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-yamux/v5"
)

// Limits and defaults.
const (
	InitialWindow          = 256 << 10 // initial stream window, go-yamux's minimum
	MaxWindow              = 16 << 20  // largest window one stream may grow to
	AgentBudget            = 32 << 20  // agent session buffer budget
	EdgeSessionBudget      = 32 << 20  // edge buffer budget per agent session
	EdgeBudget             = 256 << 20 // edge-wide buffer budget
	MeasureRTTInterval     = 10 * time.Minute
	DefaultAgentMaxStreams = AgentBudget / InitialWindow
	MaxStreamsLimit        = 4096
	AccountStreamsFree     = 256
	AccountStreamsPaid     = 1024
	PreHelloPerIP          = 20
	PreHelloPerEdge        = 512
	DeviceCallsInFlight    = 16
	ControlRatePerSec      = 50
	ControlBurst           = 200
	RateViolations         = 3
	RateViolationWindow    = 60 * time.Second
	HelloDeadline          = 10 * time.Second
	PingInterval           = 20 * time.Second
	PingTimeout            = 15 * time.Second
	EdgeSilenceLimit       = 50 * time.Second
	StreamIdleTimeout      = 3600 * time.Second
	StreamOpenTimeout      = 10 * time.Second
	StreamCloseTimeout     = 60 * time.Second
	MinSessionLifetime     = 12 * time.Hour
	MaxSessionLifetime     = 24 * time.Hour
)

// MaxStreams returns how many streams fit in budget when each may buffer a
// full window, capped at MaxStreamsLimit. It is 0 when not even one fits.
func MaxStreams(budget int64, window uint32) uint32 {
	if budget <= 0 || window == 0 {
		return 0
	}
	n := budget / int64(window)
	if n > MaxStreamsLimit {
		return MaxStreamsLimit
	}
	return uint32(n)
}

// SessionStreams returns HelloAck.max_streams: the least of the agent's
// offer, the edge's per-session cap and the account's remaining streams.
func SessionStreams(agentOffer, sessionCap, accountHeadroom uint32) uint32 {
	return min(agentOffer, sessionCap, accountHeadroom)
}

// ErrConfig reports an unusable stream count.
var ErrConfig = errors.New("tunnelwire: max streams must be 1..4096")

// YamuxConfig returns the session configuration for both sides: yamux
// keepalive off (stream 0 Ping is the only liveness probe), windows from
// 256 KiB up to 16 MiB, at most maxStreams incoming streams and an equal
// accept backlog. go-yamux still pings once at session start and then every
// MeasureRTTInterval to measure the RTT that window growth needs.
func YamuxConfig(maxStreams uint32) (*yamux.Config, error) {
	if maxStreams == 0 || maxStreams > MaxStreamsLimit {
		return nil, ErrConfig
	}
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = false
	c.MeasureRTTInterval = MeasureRTTInterval
	c.InitialStreamWindowSize = InitialWindow
	c.MaxStreamWindowSize = MaxWindow
	c.MaxIncomingStreams = maxStreams
	c.AcceptBacklog = int(maxStreams)
	c.LogOutput = io.Discard
	if err := yamux.VerifyConfig(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Budget is a byte budget. It never blocks: a reservation that does not fit
// is refused, so overload turns into backpressure, not memory growth.
type Budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	peak  int64
}

// NewBudget returns a budget of limit bytes.
func NewBudget(limit int64) *Budget { return &Budget{limit: limit} }

// TryAcquire reserves n bytes if they fit.
func (b *Budget) TryAcquire(n int64) bool {
	if n <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.limit {
		return false
	}
	b.add(n)
	return true
}

// force reserves n bytes even past the limit.
func (b *Budget) force(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.add(n)
}

func (b *Budget) add(n int64) {
	b.used += n
	b.peak = max(b.peak, b.used)
}

// Release returns n bytes. Releasing more than was acquired panics.
func (b *Budget) Release(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || n > b.used {
		panic("tunnelwire: budget released more than acquired")
	}
	b.used -= n
}

// Used returns the bytes reserved.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Peak returns the most bytes ever reserved at once.
func (b *Budget) Peak() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak
}

// ErrBudget refuses a window reservation.
var ErrBudget = errors.New("tunnelwire: stream buffer budget exhausted")

// Gate is a session's go-yamux memory manager: one span per stream, every
// span charged to the session budget and, at the edge, the global budget.
//
// go-yamux closes the whole session when an incoming stream's initial
// window cannot be reserved, so the agent gate always grants initial
// windows (their number is capped by MaxIncomingStreams) and refuses only
// growth past the budget. The edge gate refuses both: the edge opens data
// streams itself, where a refusal fails just that open, and an agent may
// not open streams other than stream 0.
type Gate struct {
	session *Budget
	shared  *Budget
	strict  bool

	mu    sync.Mutex
	spans map[*span]struct{}
	peak  int64
}

// NewAgentGate returns the agent's gate with a session budget of budget
// bytes.
func NewAgentGate(budget int64) *Gate {
	return &Gate{session: NewBudget(budget), spans: map[*span]struct{}{}}
}

// NewEdgeGate returns an edge gate with a per-session budget, charging the
// shared global budget too.
func NewEdgeGate(sessionBudget int64, global *Budget) *Gate {
	return &Gate{session: NewBudget(sessionBudget), shared: global, strict: true, spans: map[*span]struct{}{}}
}

// NewSpan is the go-yamux memory manager constructor.
func (g *Gate) NewSpan() (yamux.MemoryManager, error) {
	s := &span{g: g}
	g.mu.Lock()
	g.spans[s] = struct{}{}
	g.mu.Unlock()
	return s, nil
}

// Used returns the session's reserved bytes.
func (g *Gate) Used() int64 { return g.session.Used() }

// Peak returns the session's highest reservation.
func (g *Gate) Peak() int64 { return g.session.Peak() }

// PeakStream returns the largest reservation any one stream reached.
func (g *Gate) PeakStream() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peak
}

// SmallSpans counts live streams holding at most n bytes.
func (g *Gate) SmallSpans(n int64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := 0
	for s := range g.spans {
		if s.held > 0 && s.held <= n {
			c++
		}
	}
	return c
}

const initialPriority = 255

type span struct {
	g    *Gate
	held int64
}

func (s *span) ReserveMemory(size int, prio uint8) error {
	n := int64(size)
	if n <= 0 {
		return nil
	}
	g := s.g
	if prio == initialPriority && !g.strict {
		g.session.force(n)
	} else {
		if !g.session.TryAcquire(n) {
			return ErrBudget
		}
		if g.shared != nil && !g.shared.TryAcquire(n) {
			g.session.Release(n)
			return ErrBudget
		}
	}
	g.mu.Lock()
	s.held += n
	g.peak = max(g.peak, s.held)
	g.mu.Unlock()
	return nil
}

func (s *span) ReleaseMemory(size int) {
	g := s.g
	g.mu.Lock()
	n := min(int64(size), s.held)
	if n <= 0 {
		g.mu.Unlock()
		return
	}
	s.held -= n
	g.mu.Unlock()
	g.release(n)
}

func (s *span) Done() {
	g := s.g
	g.mu.Lock()
	n := s.held
	s.held = 0
	delete(g.spans, s)
	g.mu.Unlock()
	if n > 0 {
		g.release(n)
	}
}

func (g *Gate) release(n int64) {
	g.session.Release(n)
	if g.shared != nil {
		g.shared.Release(n)
	}
}

// Liveness tracks the time since the last received byte on a session. A
// ping is due after interval of silence; the session is dead when timeout
// more passes after the ping with still nothing received.
type Liveness struct {
	mu       sync.Mutex
	interval time.Duration
	timeout  time.Duration
	lastRx   time.Time
	pinged   bool
	pingAt   time.Time
}

// NewLiveness starts tracking at now.
func NewLiveness(interval, timeout time.Duration, now time.Time) *Liveness {
	return &Liveness{interval: interval, timeout: timeout, lastRx: now}
}

// Received records that a byte arrived at now.
func (l *Liveness) Received(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.After(l.lastRx) {
		l.lastRx = now
	}
	l.pinged = false
}

// Check returns whether to send a ping now and whether the session is dead.
// It reports a ping once per silent period.
func (l *Liveness) Check(now time.Time) (ping, dead bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastRx) < l.interval {
		return false, false
	}
	if !l.pinged {
		l.pinged, l.pingAt = true, now
		return true, false
	}
	return false, now.Sub(l.pingAt) >= l.timeout
}

// Silence returns how long nothing has been received.
func (l *Liveness) Silence(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return now.Sub(l.lastRx)
}

// LivenessConn records every byte read from the underlying connection, on
// any stream and in any frame, as liveness. Put it under the yamux session.
type LivenessConn struct {
	net.Conn
	L   *Liveness
	Now func() time.Time
}

func (c *LivenessConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.L.Received(c.Now())
	}
	return n, err
}

// SessionLifetime picks a lifetime in [12 h, 24 h], whole seconds. rnd
// returns a value in [0, n); nil uses math/rand/v2.
func SessionLifetime(rnd func(n int64) int64) time.Duration {
	if rnd == nil {
		rnd = rand.Int64N
	}
	span := int64((MaxSessionLifetime - MinSessionLifetime) / time.Second)
	return MinSessionLifetime + time.Duration(rnd(span+1))*time.Second
}
