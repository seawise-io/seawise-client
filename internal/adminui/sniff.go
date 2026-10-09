package adminui

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	DefaultPeekTimeout = 10 * time.Second
	DefaultMaxPending  = 128
)

// isTLSClientHello reports whether b starts like a TLS handshake record.
func isTLSClientHello(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

// split serves TLS and plain HTTP on one listener. Each connection is
// classified by its first bytes in its own goroutine, so a silent client
// cannot block Accept; at most maxPending connections wait to be classified.
type split struct {
	ln      net.Listener
	tls     *chanListener
	plain   *chanListener
	pending chan struct{}
	peek    time.Duration
	done    chan struct{}
	once    sync.Once
}

func splitListener(ln net.Listener, peek time.Duration, maxPending int) (tlsL, plainL net.Listener) {
	if peek <= 0 {
		peek = DefaultPeekTimeout
	}
	if maxPending <= 0 {
		maxPending = DefaultMaxPending
	}
	s := &split{ln: ln, pending: make(chan struct{}, maxPending), peek: peek, done: make(chan struct{})}
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

func (s *split) acceptLoop() {
	defer s.close()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		select {
		case s.pending <- struct{}{}:
			go s.classify(c)
		default:
			_ = c.Close()
		}
	}
}

func (s *split) classify(c net.Conn) {
	defer func() { <-s.pending }()
	_ = c.SetReadDeadline(time.Now().Add(s.peek))
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

// peekedConn replays the bytes read during classification.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
