// Package caps holds the seawise-tunnel/1 resource limits: the yamux
// configuration, stream caps derived from buffer budgets, the byte budgets
// themselves, liveness timing and session lifetime.
//
// hashicorp/yamux gives every stream the same receive window,
// MaxStreamWindowSize, from the moment it opens; it has no window
// auto-tuning. The receive buffer of one stream can therefore reach the full
// window, and a session's buffered bytes are bounded only by
// streams x window. The caps here keep that product within the budget:
// max streams = budget / window.
package caps

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Limits and defaults.
const (
	InitialWindow          = 256 << 10 // yamux's initial and minimum stream window
	AgentBudget            = 32 << 20  // agent session buffer budget
	EdgeBudget             = 256 << 20 // edge-wide buffer budget
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

// ErrConfig reports an unusable window or stream count.
var ErrConfig = errors.New("tunnelwire: window must be at least 256 KiB and max streams 1..4096")

// YamuxConfig returns the session configuration for both sides: keepalive
// off (stream 0 Ping is the only probe), the given stream window, and an
// accept backlog equal to maxStreams.
func YamuxConfig(window, maxStreams uint32) (*yamux.Config, error) {
	if window < InitialWindow || maxStreams == 0 || maxStreams > MaxStreamsLimit {
		return nil, ErrConfig
	}
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = false
	c.MaxStreamWindowSize = window
	c.AcceptBacklog = int(maxStreams)
	c.StreamOpenTimeout = StreamOpenTimeout
	c.StreamCloseTimeout = StreamCloseTimeout
	c.LogOutput = io.Discard
	if err := yamux.VerifyConfig(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Budget is a byte budget shared by streams. Acquire never blocks: a stream
// that does not fit is refused (AGENT_BUSY at the agent, 503 at the edge),
// so overload turns into backpressure, not memory growth.
type Budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
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
	b.used += n
	return true
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

// StreamGate admits a stream only when its full window fits in the session
// budget and, when shared is set, in a wider budget too (the edge's global
// budget).
type StreamGate struct {
	window  int64
	session *Budget
	shared  *Budget
}

// NewStreamGate admits streams of window bytes into a session budget of
// sessionBudget bytes and, if shared is not nil, into shared as well.
func NewStreamGate(sessionBudget int64, window uint32, shared *Budget) *StreamGate {
	return &StreamGate{window: int64(window), session: NewBudget(sessionBudget), shared: shared}
}

// Admit reserves one stream; the caller calls Done when the stream ends.
func (g *StreamGate) Admit() bool {
	if !g.session.TryAcquire(g.window) {
		return false
	}
	if g.shared != nil && !g.shared.TryAcquire(g.window) {
		g.session.Release(g.window)
		return false
	}
	return true
}

// Done releases a stream admitted by Admit.
func (g *StreamGate) Done() {
	g.session.Release(g.window)
	if g.shared != nil {
		g.shared.Release(g.window)
	}
}

// Open returns the number of admitted streams.
func (g *StreamGate) Open() int64 { return g.session.Used() / g.window }

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
