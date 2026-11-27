package wsconn

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

type msg struct {
	binary bool
	data   []byte
}

type fakeWS struct {
	in       []msg
	out      [][]byte
	writeErr error
	closed   bool
}

func (f *fakeWS) NextReader() (bool, io.Reader, error) {
	if len(f.in) == 0 {
		return false, nil, io.EOF
	}
	m := f.in[0]
	f.in = f.in[1:]
	return m.binary, bytes.NewReader(m.data), nil
}

func (f *fakeWS) WriteBinary(p []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.out = append(f.out, append([]byte(nil), p...))
	return nil
}

func (f *fakeWS) Close() error { f.closed = true; return nil }

func TestReadConcatenates(t *testing.T) {
	f := &fakeWS{in: []msg{{true, []byte("ab")}, {true, nil}, {true, []byte("cde")}}}
	got, err := io.ReadAll(New(f))
	if err != nil || string(got) != "abcde" {
		t.Fatal(string(got), err)
	}
}

func TestTextRefused(t *testing.T) {
	f := &fakeWS{in: []msg{{true, []byte("ab")}, {false, []byte("x")}, {true, []byte("c")}}}
	c := New(f)
	got, err := io.ReadAll(c)
	if !errors.Is(err, ErrTextMessage) || string(got) != "ab" {
		t.Fatal(string(got), err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, ErrTextMessage) {
		t.Fatal("error not sticky")
	}
}

func TestMessageCap(t *testing.T) {
	f := &fakeWS{in: []msg{{true, make([]byte, wire.MaxWebSocketMsg)}}}
	if got, err := io.ReadAll(New(f)); err != nil || len(got) != wire.MaxWebSocketMsg {
		t.Fatal(len(got), err)
	}
	f = &fakeWS{in: []msg{{true, make([]byte, wire.MaxWebSocketMsg+1)}}}
	if _, err := io.ReadAll(New(f)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, io.ErrClosedPipe }

type oneErrWS struct{ fakeWS }

func (o *oneErrWS) NextReader() (bool, io.Reader, error) { return true, errReader{}, nil }

func TestReaderError(t *testing.T) {
	c := New(&oneErrWS{})
	if _, err := c.Read(make([]byte, 4)); err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	if n, err := New(&fakeWS{}).Read(nil); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}

func TestWriteChunks(t *testing.T) {
	f := &fakeWS{}
	c := New(f)
	n, err := c.Write(make([]byte, 2*wire.MaxWebSocketMsg+5))
	if err != nil || n != 2*wire.MaxWebSocketMsg+5 || len(f.out) != 3 || len(f.out[2]) != 5 || len(f.out[0]) != wire.MaxWebSocketMsg {
		t.Fatal(n, err, len(f.out))
	}
	if n, err := c.Write(nil); n != 0 || err != nil || len(f.out) != 3 {
		t.Fatal("empty write sent a message")
	}
	f.writeErr = io.ErrClosedPipe
	if n, err := c.Write([]byte("x")); n != 0 || err != io.ErrClosedPipe {
		t.Fatal(n, err)
	}
	if c.Close() != nil || !f.closed {
		t.Fatal("close")
	}
}

// deadlineConn records the deadlines set on it.
type deadlineConn struct {
	net.Conn
	read, write time.Time
}

func (d *deadlineConn) SetDeadline(t time.Time) error      { d.read, d.write = t, t; return nil }
func (d *deadlineConn) SetReadDeadline(t time.Time) error  { d.read = t; return nil }
func (d *deadlineConn) SetWriteDeadline(t time.Time) error { d.write = t; return nil }

func TestNetConnForwards(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	under := &deadlineConn{Conn: a}
	nc := NetConn{Conn: New(&fakeWS{}), Under: under}
	var _ net.Conn = nc
	if nc.LocalAddr() != a.LocalAddr() || nc.RemoteAddr() != a.RemoteAddr() {
		t.Fatal("addresses not forwarded")
	}
	t1, t2, t3 := time.Unix(1, 0), time.Unix(2, 0), time.Unix(3, 0)
	if nc.SetWriteDeadline(t1) != nil || !under.write.Equal(t1) || !under.read.IsZero() {
		t.Fatal("write deadline not forwarded")
	}
	if nc.SetReadDeadline(t2) != nil || !under.read.Equal(t2) || !under.write.Equal(t1) {
		t.Fatal("read deadline not forwarded")
	}
	if nc.SetDeadline(t3) != nil || !under.read.Equal(t3) || !under.write.Equal(t3) {
		t.Fatal("deadline not forwarded")
	}
}

// stepReader returns its steps in order, each a byte count and an error.
type stepReader struct {
	data  []byte
	steps []struct {
		n   int
		err error
	}
}

func (s *stepReader) Read(p []byte) (int, error) {
	st := s.steps[0]
	s.steps = s.steps[1:]
	n := copy(p, s.data[:st.n])
	s.data = s.data[n:]
	return n, st.err
}

type readerWS struct{ rs []io.Reader }

func (r *readerWS) NextReader() (bool, io.Reader, error) {
	if len(r.rs) == 0 {
		return false, nil, io.EOF
	}
	x := r.rs[0]
	r.rs = r.rs[1:]
	return true, x, nil
}
func (r *readerWS) WriteBinary([]byte) error { return nil }
func (r *readerWS) Close() error             { return nil }

func TestReadDataWithEOFAndEmptyReads(t *testing.T) {
	// Data delivered together with EOF is kept; a (0, nil) read is retried.
	a := &stepReader{data: []byte("ab"), steps: []struct {
		n   int
		err error
	}{{2, io.EOF}}}
	b := &stepReader{data: []byte("c"), steps: []struct {
		n   int
		err error
	}{{0, nil}, {1, nil}, {0, io.EOF}}}
	c := New(&readerWS{rs: []io.Reader{a, b}})
	p := make([]byte, 8)
	if n, err := c.Read(p); n != 2 || err != nil || string(p[:2]) != "ab" {
		t.Fatal(n, err)
	}
	if n, err := c.Read(p); n != 1 || err != nil || p[0] != 'c' {
		t.Fatal(n, err)
	}
	got, err := io.ReadAll(io.LimitReader(c, 16))
	if err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
}

func TestNetConnWithoutUnder(t *testing.T) {
	nc := NetConn{Conn: New(&fakeWS{})}
	if nc.SetDeadline(time.Time{}) == nil || nc.SetReadDeadline(time.Time{}) == nil || nc.SetWriteDeadline(time.Time{}) == nil {
		t.Fatal("deadline accepted without a connection")
	}
	if nc.LocalAddr() != nil || nc.RemoteAddr() != nil {
		t.Fatal("address without a connection")
	}
}
