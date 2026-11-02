package transport

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xa

	maxControlPayload = 125
	frameReadBuffer   = 4096
	// maskChunk is how much payload is masked per write.
	maskChunk         = 16 << 10
	closeWriteTimeout = time.Second
)

// CloseError ends the WebSocket carriage.
type CloseError struct {
	Code   uint16
	Reason string
}

func (e *CloseError) Error() string {
	return "transport: websocket closed " + strconv.Itoa(int(e.Code)) + " " + e.Reason
}

var errFramesClosed = errors.New("transport: websocket closed locally")

// frames is the client end of the WebSocket carriage: masked binary frames
// out, unmasked frames in (RFC 6455 §5.1). It implements
// wsconn.MessageConn. The reader never writes: a Ping, a Pong, a Close or
// a protocol error ends the carriage without a reply, so nothing is ever
// written behind yamux's write deadline from the read side.
type frames struct {
	conn net.Conn
	br   *bufio.Reader
	mask func([]byte)

	// Read state, owned by the reading goroutine.
	rerr   error
	cur    *message
	inMsg  bool
	fin    bool
	remain uint64
	size   uint64

	wmu    sync.Mutex
	wbuf   []byte
	closed bool
}

// newFrames wraps conn after the upgrade; rest holds bytes already read
// past the upgrade response.
func newFrames(conn net.Conn, rest []byte) *frames {
	var r io.Reader = conn
	if len(rest) > 0 {
		r = io.MultiReader(&restReader{b: rest}, conn)
	}
	return &frames{conn: conn, br: bufio.NewReaderSize(r, frameReadBuffer),
		mask: func(k []byte) { _, _ = rand.Read(k) }}
}

type restReader struct{ b []byte }

func (r *restReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

type frameHeader struct {
	fin    bool
	op     byte
	length uint64
}

func (f *frames) fail(code uint16, reason string) error {
	f.rerr = &CloseError{Code: code, Reason: reason}
	return f.rerr
}

func (f *frames) ioFail(err error) error {
	f.rerr = err
	return err
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// readHeader reads and checks the next data frame header.
func (f *frames) readHeader() (frameHeader, error) {
	var b [8]byte
	if _, err := io.ReadFull(f.br, b[:2]); err != nil {
		if f.inMsg {
			err = unexpectedEOF(err)
		}
		return frameHeader{}, f.ioFail(err)
	}
	h := frameHeader{fin: b[0]&0x80 != 0, op: b[0] & 0x0f, length: uint64(b[1] & 0x7f)}
	switch {
	case b[0]&0x70 != 0, h.op > opBinary && h.op < opClose, h.op > opPong:
		return frameHeader{}, f.fail(1002, "reserved")
	case b[1]&0x80 != 0:
		return frameHeader{}, f.fail(1002, "mask")
	}
	switch h.length {
	case 126:
		if _, err := io.ReadFull(f.br, b[:2]); err != nil {
			return frameHeader{}, f.ioFail(unexpectedEOF(err))
		}
		if h.length = uint64(binary.BigEndian.Uint16(b[:2])); h.length < 126 {
			return frameHeader{}, f.fail(1002, "length")
		}
	case 127:
		if _, err := io.ReadFull(f.br, b[:8]); err != nil {
			return frameHeader{}, f.ioFail(unexpectedEOF(err))
		}
		if h.length = binary.BigEndian.Uint64(b[:8]); h.length>>63 != 0 || h.length < 1<<16 {
			return frameHeader{}, f.fail(1002, "length")
		}
	}
	if h.op >= opClose {
		switch {
		case !h.fin || h.length > maxControlPayload || h.op == opClose && h.length == 1:
			return frameHeader{}, f.fail(1002, "control")
		case h.op == opPing:
			return frameHeader{}, f.fail(1008, "ws_ping")
		case h.op == opPong:
			return frameHeader{}, f.fail(1008, "ws_pong")
		}
		return frameHeader{}, f.fail(1000, "closed")
	}
	switch {
	case f.inMsg != (h.op == opContinuation):
		return frameHeader{}, f.fail(1002, "continuation")
	case h.op == opText:
		return frameHeader{}, f.fail(1002, "text")
	}
	size := uint64(0)
	if f.inMsg {
		size = f.size
	}
	if h.length > wire.MaxWebSocketMsg-size {
		return frameHeader{}, f.fail(1009, "too_large")
	}
	return h, nil
}

// NextReader returns the next binary message; an unfinished previous
// message is skipped.
func (f *frames) NextReader() (bool, io.Reader, error) {
	if f.rerr != nil {
		return false, nil, f.rerr
	}
	for f.inMsg {
		if _, err := io.Copy(io.Discard, f.cur); err != nil {
			return false, nil, err
		}
	}
	h, err := f.readHeader()
	if err != nil {
		return false, nil, err
	}
	f.cur = &message{f: f}
	f.inMsg, f.fin, f.remain, f.size = true, h.fin, h.length, h.length
	return true, f.cur, nil
}

type message struct{ f *frames }

func (m *message) Read(p []byte) (int, error) {
	f := m.f
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if m != f.cur || !f.inMsg {
			return 0, io.EOF
		}
		if f.rerr != nil {
			return 0, f.rerr
		}
		if f.remain > 0 {
			n, err := f.br.Read(p[:min(uint64(len(p)), f.remain)])
			f.remain -= uint64(n) //nolint:gosec // G115: n <= len(p)
			if err != nil {
				return n, f.ioFail(unexpectedEOF(err))
			}
			return n, nil
		}
		if f.fin {
			f.inMsg = false
			return 0, io.EOF
		}
		h, err := f.readHeader()
		if err != nil {
			return 0, err
		}
		f.fin, f.remain, f.size = h.fin, h.length, f.size+h.length
	}
}

// WriteBinary sends p as one masked final binary frame.
func (f *frames) WriteBinary(p []byte) error {
	if len(p) > wire.MaxWebSocketMsg {
		return errors.New("transport: websocket message over 1 MiB")
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.closed {
		return errFramesClosed
	}
	return f.writeLocked(opBinary, p)
}

func (f *frames) writeLocked(op byte, p []byte) error {
	var key [4]byte
	f.mask(key[:])
	hdr := f.wbuf[:0]
	hdr = append(hdr, 0x80|op)
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n < 1<<16:
		hdr = append(hdr, 0x80|126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n)) //nolint:gosec // G115: n < 65536
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	hdr = append(hdr, key[:]...)
	buf := hdr
	pos := 0
	for {
		k := min(len(p)-pos, maskChunk)
		start := len(buf)
		buf = append(buf, p[pos:pos+k]...)
		for i := range k {
			buf[start+i] ^= key[(pos+i)&3]
		}
		pos += k
		if _, err := f.conn.Write(buf); err != nil {
			f.wbuf = buf[:0]
			return err
		}
		buf = buf[:0]
		if pos == len(p) {
			f.wbuf = buf
			return nil
		}
	}
}

// Close sends a normal Close when no writer holds the connection, then
// closes it.
func (f *frames) Close() error {
	if f.wmu.TryLock() {
		if !f.closed {
			f.closed = true
			_ = f.conn.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
			_ = f.writeLocked(opClose, binary.BigEndian.AppendUint16(nil, 1000))
		}
		f.wmu.Unlock()
	}
	return f.conn.Close()
}
