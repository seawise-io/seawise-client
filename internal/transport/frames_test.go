package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
	"github.com/seawise-io/seawise-client/tunnelwire/wsconn"
)

// scriptConn reads from r and records writes and write deadlines.
type scriptConn struct {
	r        io.Reader
	mu       sync.Mutex
	w        bytes.Buffer
	writeErr error
	wdl      time.Time
	closed   bool
}

func (c *scriptConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.w.Write(p)
}
func (c *scriptConn) Close() error                       { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *scriptConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *scriptConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *scriptConn) SetDeadline(time.Time) error        { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error    { return nil }
func (c *scriptConn) SetWriteDeadline(t time.Time) error { c.wdl = t; return nil }
func (c *scriptConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.w.Bytes())
}

func frame(b0 byte, p []byte) []byte {
	var buf bytes.Buffer
	_ = writeServerFrame(&buf, b0, p)
	return buf.Bytes()
}

func readAll(f *frames) ([]byte, error) { return io.ReadAll(wsconn.New(f)) }

func TestFramesRFCVectors(t *testing.T) {
	// RFC 6455 §5.7 with the binary opcode: one unmasked frame, a fragmented
	// message, 256 bytes and 64 KiB with extended lengths.
	in := []byte{0x82, 0x05, 'H', 'e', 'l', 'l', 'o', 0x02, 0x03, 'H', 'e', 'l', 0x80, 0x02, 'l', 'o'}
	in = append(in, 0x82, 0x7e, 0x01, 0x00)
	in = append(in, bytes.Repeat([]byte{1}, 256)...)
	in = append(in, 0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0)
	in = append(in, bytes.Repeat([]byte{2}, 65536)...)
	f := newFrames(&scriptConn{r: bytes.NewReader(in)}, nil)
	got, err := readAll(f)
	want := append(append([]byte("HelloHello"), bytes.Repeat([]byte{1}, 256)...), bytes.Repeat([]byte{2}, 65536)...)
	if !bytes.Equal(got, want) || !errors.Is(err, io.EOF) && err != nil {
		t.Fatal(len(got), err)
	}
}

func TestFramesMaskedWrite(t *testing.T) {
	c := &scriptConn{r: bytes.NewReader(nil)}
	f := newFrames(c, nil)
	f.mask = func(k []byte) { copy(k, []byte{0x37, 0xfa, 0x21, 0x3d}) }
	if err := f.WriteBinary([]byte("Hello")); err != nil {
		t.Fatal(err)
	}
	// RFC 6455 §5.7 masked "Hello", binary opcode.
	if want := []byte{0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}; !bytes.Equal(c.written(), want) {
		t.Fatalf("%x", c.written())
	}
}

// unmask reads one client frame from b.
func unmaskFrame(t *testing.T, b []byte) (byte, []byte, []byte) {
	t.Helper()
	if b[1]&0x80 == 0 {
		t.Fatal("client frame not masked")
	}
	n, off := uint64(b[1]&0x7f), 2
	switch n {
	case 126:
		n, off = uint64(binary.BigEndian.Uint16(b[2:])), 4
	case 127:
		n, off = binary.BigEndian.Uint64(b[2:]), 10
	}
	k := b[off : off+4]
	p := bytes.Clone(b[off+4 : off+4+int(n)])
	for i := range p {
		p[i] ^= k[i&3]
	}
	return b[0], p, b[off+4+int(n):]
}

func TestFramesWriteSizes(t *testing.T) {
	for _, n := range []int{0, 125, 126, 65535, 65536, maskChunk + 7, wire.MaxWebSocketMsg} {
		c := &scriptConn{r: bytes.NewReader(nil)}
		f := newFrames(c, nil)
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i * 7)
		}
		if err := f.WriteBinary(p); err != nil {
			t.Fatal(n, err)
		}
		b0, got, rest := unmaskFrame(t, c.written())
		if b0 != 0x82 || !bytes.Equal(got, p) || len(rest) != 0 {
			t.Fatal(n, b0, len(got), len(rest))
		}
	}
	f := newFrames(&scriptConn{r: bytes.NewReader(nil)}, nil)
	if err := f.WriteBinary(make([]byte, wire.MaxWebSocketMsg+1)); err == nil {
		t.Fatal("over 1 MiB sent")
	}
	c := &scriptConn{r: bytes.NewReader(nil), writeErr: io.ErrClosedPipe}
	if err := newFrames(c, nil).WriteBinary(make([]byte, maskChunk*2)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestFramesMaskKeysDiffer(t *testing.T) {
	c := &scriptConn{r: bytes.NewReader(nil)}
	f := newFrames(c, nil)
	_ = f.WriteBinary([]byte("a"))
	_ = f.WriteBinary([]byte("a"))
	w := c.written()
	if bytes.Equal(w[2:6], w[9:13]) {
		t.Fatal("mask key reused")
	}
}

// failingPayload fails the test if the payload is ever read.
type failingPayload struct {
	t      *testing.T
	header []byte
}

func (r *failingPayload) Read(p []byte) (int, error) {
	if len(r.header) == 0 {
		r.t.Fatal("payload read after an oversized header")
	}
	n := copy(p, r.header)
	r.header = r.header[n:]
	return n, nil
}

func TestFramesRefusals(t *testing.T) {
	big := func(n uint64) []byte {
		return binary.BigEndian.AppendUint64([]byte{0x82, 0x7f}, n)
	}
	cases := []struct {
		name   string
		in     []byte
		code   uint16
		reason string
	}{
		{"rsv1", frame(0xc2, []byte("x")), 1002, "reserved"},
		{"rsv3", frame(0x92, []byte("x")), 1002, "reserved"},
		{"opcode 3", frame(0x83, []byte("x")), 1002, "reserved"},
		{"opcode 11", frame(0x8b, nil), 1002, "reserved"},
		{"masked", []byte{0x82, 0x81, 1, 2, 3, 4, 'x'}, 1002, "mask"},
		{"text", frame(0x81, []byte("x")), 1002, "text"},
		{"stray continuation", frame(0x80, []byte("x")), 1002, "continuation"},
		{"data inside message", append(frame(0x02, []byte("x")), frame(0x82, []byte("y"))...), 1002, "continuation"},
		{"short 16-bit length", []byte{0x82, 0x7e, 0x00, 0x7d}, 1002, "length"},
		{"short 64-bit length", big(65535), 1002, "length"},
		{"64-bit msb", big(1 << 63), 1002, "length"},
		{"ping", frame(0x89, nil), 1008, "ws_ping"},
		{"pong", frame(0x8a, []byte("x")), 1008, "ws_pong"},
		{"ping inside message", append(frame(0x02, []byte("x")), frame(0x89, nil)...), 1008, "ws_ping"},
		{"close", frame(0x88, []byte{0x03, 0xe8}), 1000, "closed"},
		{"close empty", frame(0x88, nil), 1000, "closed"},
		{"close one byte", frame(0x88, []byte{1}), 1002, "control"},
		{"control not final", frame(0x09, nil), 1002, "control"},
		{"control too long", append([]byte{0x89, 0x7e, 0x00, 0x7e}, make([]byte, 126)...), 1002, "control"},
	}
	for _, c := range cases {
		sc := &scriptConn{r: bytes.NewReader(c.in)}
		_, err := readAll(newFrames(sc, nil))
		var ce *CloseError
		if !errors.As(err, &ce) || ce.Code != c.code || ce.Reason != c.reason {
			t.Errorf("%s: %v", c.name, err)
		}
		if len(sc.written()) != 0 {
			t.Errorf("%s: the reader wrote %x", c.name, sc.written())
		}
	}
}

func TestFramesSizeLimit(t *testing.T) {
	exact := append([]byte{0x82, 0x7f}, binary.BigEndian.AppendUint64(nil, wire.MaxWebSocketMsg)...)
	got, err := readAll(newFrames(&scriptConn{r: bytes.NewReader(append(exact, make([]byte, wire.MaxWebSocketMsg)...))}, nil))
	if err != nil || len(got) != wire.MaxWebSocketMsg {
		t.Fatal(len(got), err)
	}
	over := append([]byte{0x82, 0x7f}, binary.BigEndian.AppendUint64(nil, wire.MaxWebSocketMsg+1)...)
	_, err = readAll(newFrames(&scriptConn{r: &failingPayload{t: t, header: over}}, nil))
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != 1009 || ce.Reason != "too_large" {
		t.Fatal(err)
	}
	// Fragments add up: 1 MiB in two fragments passes, one byte more does not.
	half := wire.MaxWebSocketMsg / 2
	in := append(append([]byte{0x02, 0x7f}, binary.BigEndian.AppendUint64(nil, uint64(half))...), make([]byte, half)...)
	in2 := append(bytes.Clone(in), append([]byte{0x80, 0x7f}, binary.BigEndian.AppendUint64(nil, uint64(half))...)...)
	got, err = readAll(newFrames(&scriptConn{r: bytes.NewReader(append(in2, make([]byte, half)...))}, nil))
	if err != nil || len(got) != wire.MaxWebSocketMsg {
		t.Fatal(len(got), err)
	}
	in3 := append(bytes.Clone(in), append([]byte{0x80, 0x7f}, binary.BigEndian.AppendUint64(nil, uint64(half+1))...)...)
	_, err = readAll(newFrames(&scriptConn{r: &failingPayload{t: t, header: in3}}, nil))
	if !errors.As(err, &ce) || ce.Code != 1009 {
		t.Fatal(err)
	}
}

func TestFramesTruncated(t *testing.T) {
	for _, in := range [][]byte{{0x82, 0x7e, 0x01}, {0x82, 0x7f, 0, 0}, {0x82, 0x05, 'a'}, append(frame(0x02, []byte("a")), 0x80)} {
		_, err := readAll(newFrames(&scriptConn{r: bytes.NewReader(in)}, nil))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%x: %v", in, err)
		}
	}
	// A partial header between messages is not a clean end either.
	if _, err := readAll(newFrames(&scriptConn{r: bytes.NewReader([]byte{0x82})}, nil)); err == nil {
		t.Error("half a header read as the end")
	}
	// A clean end between messages is EOF.
	if _, _, err := newFrames(&scriptConn{r: bytes.NewReader(nil)}, nil).NextReader(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestFramesRestFirst(t *testing.T) {
	f := newFrames(&scriptConn{r: bytes.NewReader(frame(0x82, []byte("cd")))}, frame(0x82, []byte("ab")))
	got, _ := readAll(f)
	if string(got) != "abcd" {
		t.Fatal(string(got))
	}
}

func TestFramesSkipUnreadMessage(t *testing.T) {
	f := newFrames(&scriptConn{r: bytes.NewReader(append(frame(0x82, []byte("abc")), frame(0x82, []byte("d"))...))}, nil)
	_, r1, err := f.NextReader()
	if err != nil {
		t.Fatal(err)
	}
	_, r2, err := f.NextReader()
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r1); len(b) != 0 {
		t.Fatal("old reader still reads")
	}
	if b, _ := io.ReadAll(r2); string(b) != "d" {
		t.Fatal(string(b))
	}
	if n, err := r2.Read(nil); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	if _, _, err := f.NextReader(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if _, _, err := f.NextReader(); !errors.Is(err, io.EOF) {
		t.Fatal("error not sticky", err)
	}
}

func TestFramesClose(t *testing.T) {
	c := &scriptConn{r: bytes.NewReader(nil)}
	f := newFrames(c, nil)
	if err := f.Close(); err != nil || !c.closed || c.wdl.IsZero() {
		t.Fatal(err, c.closed)
	}
	b0, p, _ := unmaskFrame(t, c.written())
	if b0 != 0x88 || !bytes.Equal(p, []byte{0x03, 0xe8}) {
		t.Fatalf("%x %x", b0, p)
	}
	if err := f.WriteBinary([]byte("x")); !errors.Is(err, errFramesClosed) {
		t.Fatal(err)
	}
	_ = f.Close()
	if n := len(c.written()); n != 8 {
		t.Fatal("second Close frame", n)
	}
	// A writer holding the connection: Close does not wait to send a frame.
	c2 := &scriptConn{r: bytes.NewReader(nil)}
	f2 := newFrames(c2, nil)
	f2.wmu.Lock()
	if err := f2.Close(); err != nil || !c2.closed || len(c2.written()) != 0 {
		t.Fatal("close waited for the writer")
	}
	f2.wmu.Unlock()
}

func FuzzClientFrames(f *testing.F) {
	f.Add(frame(0x82, []byte("Hello")))
	f.Add(append(frame(0x02, []byte("He")), frame(0x80, []byte("llo"))...))
	f.Add(frame(0x89, nil))
	f.Add([]byte{0x82, 0x7e, 0x00, 0x80})
	f.Fuzz(func(t *testing.T, in []byte) {
		sc := &scriptConn{r: bytes.NewReader(in)}
		got, err := readAll(newFrames(sc, nil))
		if len(got) > len(in) {
			t.Fatal("more payload than input")
		}
		if len(sc.written()) != 0 {
			t.Fatal("the reader wrote")
		}
		var ce *CloseError
		if err != nil && !errors.As(err, &ce) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, wsconn.ErrTooLarge) {
			t.Fatal(err)
		}
		if ce != nil {
			switch ce.Code {
			case 1000, 1002, 1008, 1009:
			default:
				t.Fatal(ce)
			}
		}
	})
}
