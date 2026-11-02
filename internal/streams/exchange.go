package streams

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/httpwire"

	"github.com/seawise/client/internal/accesslog"
)

// MaxResponseHead caps each response head from the app.
const MaxResponseHead = httpwire.MaxHeaderBytes

const bufSize = 32 << 10

var errHead = errors.New("streams: bad response head")

// upstream is the app connection.
type upstream interface {
	io.ReadWriter
	Close() error
	CloseWrite() error
}

// exchange carries one request and its response between a stream and an
// app connection.
type exchange struct {
	s        *Server
	st       stream
	up       upstream
	in, out  atomic.Int64
	base     time.Time    // monotonic start
	last     atomic.Int64 // nanoseconds from base to the last byte either way
	upgraded atomic.Bool
	once     sync.Once
	aborted  atomic.Bool
}

func newExchange(s *Server, st stream, up upstream) *exchange {
	return &exchange{s: s, st: st, up: up, base: time.Now()}
}

func (x *exchange) touch() { x.last.Store(int64(time.Since(x.base))) }

// idleFor is the time since the last byte either way.
func (x *exchange) idleFor() time.Duration { return time.Since(x.base) - time.Duration(x.last.Load()) }

// abort resets the stream and closes the app connection.
func (x *exchange) abort() {
	x.once.Do(func() {
		x.aborted.Store(true)
		x.s.reset(x.st)
		_ = x.up.Close()
	})
}

type meterReader struct {
	r io.Reader
	x *exchange
}

func (m meterReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > 0 {
		m.x.touch()
	}
	return n, err
}

type meterWriter struct {
	w io.Writer
	n *atomic.Int64
	x *exchange
}

func (m meterWriter) Write(p []byte) (int, error) {
	n, err := m.w.Write(p)
	m.n.Add(int64(n))
	if n > 0 {
		m.x.touch()
	}
	return n, err
}

// watch aborts the exchange after IdleTimeout without a byte either way.
func (x *exchange) watch(done <-chan struct{}) {
	idle := x.s.cfg.IdleTimeout
	tick := time.NewTicker(max(idle/8, 5*time.Millisecond))
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			if x.idleFor() > idle {
				x.abort()
				return
			}
		}
	}
}

// run returns the access log result.
func (x *exchange) run() string {
	x.touch()
	done := make(chan struct{})
	defer close(done)
	go x.watch(done)

	toApp := meterWriter{w: x.up, n: &x.in, x: x}
	br := bufio.NewReaderSize(meterReader{r: x.st, x: x}, bufSize)
	_ = x.st.SetReadDeadline(time.Now().Add(x.s.cfg.HeadTimeout))
	req, err := httpwire.ReadRequest(br)
	_ = x.st.SetReadDeadline(time.Time{})
	if err != nil {
		x.abort()
		return accesslog.ResultMalformed
	}
	httpwire.StripSeaWise(req.Header)
	upgrade := webSocket(req)
	if !upgrade {
		req.Header.Del("Upgrade")
	}

	resp := make(chan error, 1)
	go func() { resp <- x.response(req, upgrade) }()
	finish := func(result string) string {
		x.abort()
		<-resp
		return result
	}

	if err := writeRequest(toApp, req, upgrade); err != nil {
		if httpwire.CodeOf(err) != "" {
			return finish(accesslog.ResultMalformed)
		}
		return finish(accesslog.ResultOK)
	}
	if !upgrade {
		if httpwire.Ended(br) != nil {
			return finish(accesslog.ResultMalformed)
		}
		switch err := httpwire.Trailing(br); {
		case httpwire.CodeOf(err) == httpwire.CodeTrailing:
			return finish(accesslog.ResultMalformed)
		case err != nil:
			return finish(accesslog.ResultOK)
		}
		return x.closeWait(resp)
	}
	if _, err := br.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return x.closeWait(resp)
		}
		return finish(accesslog.ResultOK)
	}
	if !x.upgraded.Load() {
		return finish(accesslog.ResultMalformed)
	}
	if _, err := io.Copy(toApp, br); err != nil {
		return finish(accesslog.ResultOK)
	}
	return x.closeWait(resp)
}

// closeWait ends the exchange after the edge's FIN: the app gets a
// half-close and CloseWait to finish its response.
func (x *exchange) closeWait(resp <-chan error) string {
	_ = x.up.CloseWrite()
	t := time.NewTimer(x.s.cfg.CloseWait)
	defer t.Stop()
	select {
	case <-resp:
		x.closeStream()
	case <-t.C:
		x.abort()
		<-resp
	}
	return accesslog.ResultOK
}

func (x *exchange) closeStream() {
	if !x.aborted.Load() {
		_ = x.st.Close()
	}
}

// response copies the app's response heads byte for byte, marks the
// stream upgraded before forwarding a 101 to an upgrade request, then
// copies the rest raw and half-closes the stream. Any failure aborts.
func (x *exchange) response(req *http.Request, upgrade bool) error {
	rb := bufio.NewReaderSize(meterReader{r: x.up, x: x}, bufSize)
	toEdge := meterWriter{w: x.st, n: &x.out, x: x}
	for {
		head, status, err := readHead(rb)
		if err != nil {
			x.abort()
			return err
		}
		final := status >= 200
		if status == http.StatusSwitchingProtocols {
			if !upgrade || !upgradesTo(head, "websocket") || httpwire.RawAfter(req, status) != nil {
				x.abort()
				return errHead
			}
			x.upgraded.Store(true)
			final = true
		}
		if _, err := toEdge.Write(head); err != nil {
			x.abort()
			return err
		}
		if final {
			break
		}
	}
	if _, err := io.Copy(toEdge, rb); err != nil {
		x.abort()
		return err
	}
	_ = x.st.CloseWrite()
	return nil
}

// webSocket reports whether req is a WebSocket upgrade: Upgrade is exactly
// websocket and the request has no body framing. No other protocol is
// carried past the request.
func webSocket(req *http.Request) bool {
	vs := req.Header.Values("Upgrade")
	return len(vs) == 1 && strings.EqualFold(strings.TrimSpace(vs[0]), "websocket") && httpwire.AsksUpgrade(req) &&
		len(req.TransferEncoding) == 0 && req.ContentLength == 0 && len(req.Header.Values("Content-Length")) == 0
}

// upgradesTo reports whether a response head has exactly one Upgrade
// field and it names proto.
func upgradesTo(head []byte, proto string) bool {
	n, ok := 0, false
	lines := strings.Split(string(head), "\n")
	for _, l := range lines[1:] {
		name, value, found := strings.Cut(strings.TrimRight(l, "\r"), ":")
		if !found || !strings.EqualFold(name, "upgrade") {
			continue
		}
		n++
		ok = strings.EqualFold(strings.Trim(value, " \t"), proto)
	}
	return n == 1 && ok
}

// readHead reads one response head (status line to the empty line), at
// most MaxResponseHead bytes, and returns it unchanged with its status.
func readHead(r *bufio.Reader) ([]byte, int, error) {
	var head []byte
	for {
		start := len(head)
		for {
			part, err := r.ReadSlice('\n')
			if len(head)+len(part) > MaxResponseHead {
				return nil, 0, errHead
			}
			head = append(head, part...)
			if err == nil {
				break
			}
			if !errors.Is(err, bufio.ErrBufferFull) {
				return nil, 0, err
			}
		}
		if line := string(head[start:]); start > 0 && (line == "\r\n" || line == "\n") {
			break
		}
	}
	status, ok := statusOf(head)
	if !ok {
		return nil, 0, errHead
	}
	return head, status, nil
}

// statusOf parses "HTTP/1.x NNN" at the start of a head.
func statusOf(head []byte) (int, bool) {
	if len(head) < 13 || string(head[:7]) != "HTTP/1." || head[7] < '0' || head[7] > '9' || head[8] != ' ' {
		return 0, false
	}
	n, err := strconv.Atoi(string(head[9:12]))
	if err != nil || n < 100 || n > 999 {
		return 0, false
	}
	if c := head[12]; c != ' ' && c != '\r' && c != '\n' {
		return 0, false
	}
	return n, true
}

// writeRequest writes req as received, except for the fields this agent
// controls: framing, and Connection: close unless the request upgrades.
// Nothing else is added.
func writeRequest(w io.Writer, req *http.Request, upgrade bool) error {
	h := req.Header.Clone()
	for _, k := range []string{"Host", "Content-Length", "Transfer-Encoding"} {
		delete(h, k)
	}
	if !upgrade {
		h.Set("Connection", "close")
	}
	chunked := len(req.TransferEncoding) > 0
	bw := bufio.NewWriterSize(w, bufSize)
	fmt.Fprintf(bw, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.RequestURI, req.Host)
	switch {
	case chunked:
		_, _ = io.WriteString(bw, "Transfer-Encoding: chunked\r\n")
	case req.ContentLength > 0:
		fmt.Fprintf(bw, "Content-Length: %d\r\n", req.ContentLength)
	}
	_ = h.Write(bw)
	_, _ = io.WriteString(bw, "\r\n")
	if err := bw.Flush(); err != nil {
		return err
	}
	switch {
	case chunked:
		cw := httputil.NewChunkedWriter(w)
		if _, err := io.Copy(cw, req.Body); err != nil {
			return err
		}
		if err := cw.Close(); err != nil {
			return err
		}
		bw.Reset(w)
		_ = req.Trailer.Write(bw)
		_, _ = io.WriteString(bw, "\r\n")
		return bw.Flush()
	case req.ContentLength > 0:
		_, err := io.Copy(w, req.Body)
		return err
	}
	return nil
}
