package adminui

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	DefaultPeekTimeout = 3 * time.Second
	DefaultMaxConns    = 128
	DefaultMaxPerIP    = 16
)

// isTLSClientHello reports whether b starts like a TLS handshake record.
func isTLSClientHello(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

type limits struct {
	peek  time.Duration
	total int
	perIP int
}

func (l limits) withDefaults() limits {
	if l.peek <= 0 {
		l.peek = DefaultPeekTimeout
	}
	if l.total <= 0 {
		l.total = DefaultMaxConns
	}
	if l.perIP <= 0 {
		l.perIP = DefaultMaxPerIP
	}
	return l
}

// split serves TLS and plain HTTP on one listener. Each connection is
// classified by its first bytes in its own goroutine, so a silent client
// cannot block Accept. A connection holds its slot in the total and
// per-address caps until it is closed.
type split struct {
	ln     net.Listener
	lim    limits
	tls    *chanListener
	plain  *chanListener
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	open   int
	byPeer map[string]int
}

func splitListener(ln net.Listener, lim limits) (tlsL, plainL net.Listener) {
	s := &split{ln: ln, lim: lim.withDefaults(), done: make(chan struct{}), byPeer: map[string]int{}}
	s.tls = &chanListener{s: s, ch: make(chan net.Conn)}
	s.plain = &chanListener{s: s, ch: make(chan net.Conn)}
	go s.acceptLoop()
	return s.tls, s.plain
}

func (s *split) close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.ln.Close()
	})
	return err
}

// acceptLoop retries every error except a closed listener, backing off so
// a burst of failures (for example running out of file descriptors) does
// not spin.
func (s *split) acceptLoop() {
	defer s.close()
	delay := 5 * time.Millisecond
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-s.done:
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, time.Second)
			continue
		}
		delay = 5 * time.Millisecond
		lc, ok := s.admit(c)
		if !ok {
			_ = c.Close()
			continue
		}
		go s.classify(lc)
	}
}

func peerKey(addr net.Addr) string {
	if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
		return ap.Addr().Unmap().String()
	}
	return addr.String()
}

func (s *split) admit(c net.Conn) (net.Conn, bool) {
	key := peerKey(c.RemoteAddr())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open >= s.lim.total || s.byPeer[key] >= s.lim.perIP {
		return nil, false
	}
	s.open++
	s.byPeer[key]++
	return &limitedConn{Conn: c, release: func() { s.release(key) }}, true
}

func (s *split) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open--
	if s.byPeer[key]--; s.byPeer[key] <= 0 {
		delete(s.byPeer, key)
	}
}

func (s *split) classify(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(s.lim.peek))
	br := bufio.NewReader(c)
	b, err := br.Peek(3)
	if len(b) == 0 || (err != nil && !errors.Is(err, io.EOF)) {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pc := &peekedConn{Conn: c, r: br}
	target := s.plain
	if isTLSClientHello(b) {
		target = s.tls
	}
	select {
	case target.ch <- pc:
	case <-s.done:
		_ = c.Close()
	}
}

type chanListener struct {
	s  *split
	ch chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.s.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error   { return l.s.close() }
func (l *chanListener) Addr() net.Addr { return l.s.ln.Addr() }

// limitedConn gives its slot back exactly once, when closed.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// peekedConn replays the bytes read during classification.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
