package testedge

import (
	"net"
	"slices"
	"sort"
	"sync"
	"time"
)

// TCPHeader is the IPv4 and TCP header with timestamps that every segment
// adds on the wire.
const TCPHeader = 52

// Sample is the kernel's count for one connection at one moment: payload
// bytes sent (with retransmissions) and received, and segments both ways
// (pure ACKs included).
type Sample struct {
	At      time.Time
	Sent    uint64
	Recv    uint64
	SegsIn  uint64
	SegsOut uint64
}

// Wire is the bytes on the wire between two samples.
func Wire(a, b Sample) int64 {
	return int64(b.Sent-a.Sent+b.Recv-a.Recv) + TCPHeader*int64(b.SegsIn-a.SegsIn+b.SegsOut-a.SegsOut)
}

// Mark is a stream 0 message the edge decoded or sent.
type Mark struct {
	At   time.Time
	Kind string
}

// Burst is a run of activity on a connection with no quiet gap inside.
type Burst struct {
	Start, End time.Time
	Bytes      int64
	Segments   int64
	Kinds      []string
}

// Kind names a burst by the messages in it: "start" (Hello), a single
// device call ("call:LIST_APPS"), "ping", "transport" (no stream 0
// message: yamux pings and window updates) or "mixed".
func (b Burst) Kind() string {
	switch {
	case slices.Contains(b.Kinds, "hello"):
		return "start"
	case len(b.Kinds) == 0:
		return "transport"
	}
	var calls []string
	ping := false
	for _, k := range b.Kinds {
		switch {
		case k == "ping":
			ping = true
		case len(k) > 5 && k[:5] == "call:":
			calls = append(calls, k)
		}
	}
	switch {
	case len(calls) == 1 && !ping:
		return calls[0]
	case len(calls) == 0 && ping:
		return "ping"
	case len(calls) == 0:
		return "transport"
	}
	return "mixed"
}

// meter samples one tunnel connection.
type meter struct {
	conn net.Conn
	stop chan struct{}

	mu      sync.Mutex
	samples []Sample
	marks   []Mark
}

const sampleEvery = 10 * time.Millisecond

func newMeter(c net.Conn) *meter {
	m := &meter{conn: c, stop: make(chan struct{})}
	if s, ok := readTCPInfo(c); ok {
		m.samples = append(m.samples, s)
		go m.run()
	}
	return m
}

func (m *meter) run() {
	t := time.NewTicker(sampleEvery)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
		}
		s, ok := readTCPInfo(m.conn)
		if !ok {
			return
		}
		m.mu.Lock()
		last := m.samples[len(m.samples)-1]
		if s.Sent != last.Sent || s.Recv != last.Recv || s.SegsIn != last.SegsIn || s.SegsOut != last.SegsOut {
			m.samples = append(m.samples, s)
		}
		m.mu.Unlock()
	}
}

func (m *meter) mark(kind string) {
	m.mu.Lock()
	m.marks = append(m.marks, Mark{At: time.Now(), Kind: kind})
	m.mu.Unlock()
}

func (m *meter) close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
}

// Bursts splits the samples taken in [from, to) into bursts separated by
// at least gap of quiet, each labelled with the marks inside it.
func (m *meter) bursts(from, to time.Time, gap time.Duration) []Burst {
	m.mu.Lock()
	samples := slices.Clone(m.samples)
	marks := slices.Clone(m.marks)
	m.mu.Unlock()
	return Bursts(samples, marks, from, to, gap)
}

// Bursts is the analysis behind a meter, exposed for tests.
func Bursts(samples []Sample, marks []Mark, from, to time.Time, gap time.Duration) []Burst {
	var out []Burst
	var prev *Sample
	for i := range samples {
		s := &samples[i]
		if s.At.Before(from) {
			prev = s
			continue
		}
		if !s.At.Before(to) || prev == nil {
			if prev == nil {
				prev = s
				continue
			}
			break
		}
		b := Wire(*prev, *s)
		segs := int64(s.SegsIn - prev.SegsIn + s.SegsOut - prev.SegsOut)
		if n := len(out); n > 0 && s.At.Sub(out[n-1].End) < gap {
			out[n-1].End = s.At
			out[n-1].Bytes += b
			out[n-1].Segments += segs
		} else {
			// Samples are kept only on change: the activity began within one
			// sampling period before this one.
			out = append(out, Burst{Start: s.At.Add(-sampleEvery), End: s.At, Bytes: b, Segments: segs})
		}
		prev = s
	}
	for i := range out {
		for _, mk := range marks {
			if !mk.At.Before(out[i].Start.Add(-gap/2)) && mk.At.Before(out[i].End.Add(gap/2)) {
				out[i].Kinds = append(out[i].Kinds, mk.Kind)
			}
		}
	}
	return out
}

// Median of the burst sizes of one kind, and how many there were.
func Median(bursts []Burst, kind string) (int64, int) {
	var v []int64
	for _, b := range bursts {
		if b.Kind() == kind {
			v = append(v, b.Bytes)
		}
	}
	if len(v) == 0 {
		return 0, 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2], len(v)
}

// CountingListener totals the wire bytes of every connection it accepted,
// for traffic that is not a tunnel session (the update repository).
type CountingListener struct {
	net.Listener

	mu    sync.Mutex
	done  int64
	conns map[*countedConn]Sample
}

// Count wraps ln.
func Count(ln net.Listener) *CountingListener {
	return &CountingListener{Listener: ln, conns: map[*countedConn]Sample{}}
}

type countedConn struct {
	net.Conn
	l    *CountingListener
	once sync.Once
}

// Accept counts the connection from its TCP handshake.
func (l *CountingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	base, _ := readTCPInfo(c)
	cc := &countedConn{Conn: c, l: l}
	l.mu.Lock()
	l.conns[cc] = base
	l.mu.Unlock()
	return cc, nil
}

func (c *countedConn) Close() error {
	c.once.Do(func() {
		s, ok := readTCPInfo(c.Conn)
		c.l.mu.Lock()
		if base, found := c.l.conns[c]; found && ok {
			// The handshake (3 segments) and the close (4) are added.
			c.l.done += Wire(base, s) + 7*TCPHeader
		}
		delete(c.l.conns, c)
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

// Wire is the total so far, open connections included.
func (l *CountingListener) Wire() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	total := l.done
	for c, base := range l.conns {
		if s, ok := readTCPInfo(c.Conn); ok {
			total += Wire(base, s) + 7*TCPHeader
		}
	}
	return total
}
