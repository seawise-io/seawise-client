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

func TestNetConn(t *testing.T) {
	a := &net.TCPAddr{Port: 1}
	nc := NetConn{Conn: New(&fakeWS{}), Local: a, Remote: a}
	var _ net.Conn = nc
	if nc.LocalAddr() != a || nc.RemoteAddr() != a || nc.SetDeadline(time.Time{}) == nil || nc.SetReadDeadline(time.Time{}) == nil || nc.SetWriteDeadline(time.Time{}) == nil {
		t.Fatal()
	}
}
