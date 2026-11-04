package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"
)

// PartialFrameTimeout bounds how long a control frame may stay incomplete
// once its first byte arrived.
const PartialFrameTimeout = 15 * time.Second

// AppendControlFrame appends the uint32 big-endian length of msg and msg.
func AppendControlFrame(dst, msg []byte) ([]byte, error) {
	if len(msg) == 0 {
		return dst, fail(CodeEmpty, "control")
	}
	if len(msg) > MaxControlMessage {
		return dst, fail(CodeTooLarge, "control")
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(msg)))
	return append(dst, msg...), nil
}

// ControlReader reads length-prefixed control frames from stream 0.
type ControlReader struct {
	r           io.Reader
	setDeadline func(time.Time) error
	now         func() time.Time
	hdr         [4]byte
}

// NewControlReader reads frames from r. setDeadline, when not nil, sets
// the read deadline of r; it bounds a partial frame to
// PartialFrameTimeout and is cleared between frames.
func NewControlReader(r io.Reader, setDeadline func(time.Time) error) *ControlReader {
	return &ControlReader{r: r, setDeadline: setDeadline, now: time.Now}
}

// Next returns the next frame's message bytes. It returns io.EOF only at a
// frame boundary. The length is checked before the message is allocated.
func (c *ControlReader) Next() ([]byte, error) {
	if c.setDeadline != nil {
		if err := c.setDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}
	if _, err := io.ReadFull(c.r, c.hdr[:1]); err != nil {
		return nil, err
	}
	if c.setDeadline != nil {
		if err := c.setDeadline(c.now().Add(PartialFrameTimeout)); err != nil {
			return nil, err
		}
	}
	if _, err := io.ReadFull(c.r, c.hdr[1:]); err != nil {
		return nil, readErr(err)
	}
	n := binary.BigEndian.Uint32(c.hdr[:])
	if n == 0 {
		return nil, fail(CodeEmpty, "control")
	}
	if n > MaxControlMessage {
		return nil, fail(CodeTooLarge, "control")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(c.r, msg); err != nil {
		return nil, readErr(err)
	}
	return msg, nil
}

func readErr(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fail(CodeTruncated, "frame")
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fail(CodeTimeout, "frame")
	}
	return err
}

// appendFrame16 appends a uint16 big-endian length and msg, 1..max bytes.
func appendFrame16(dst, msg []byte, max int, field string) ([]byte, error) {
	if len(msg) == 0 {
		return dst, fail(CodeEmpty, field)
	}
	if len(msg) > max {
		return dst, fail(CodeTooLarge, field)
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(msg)))
	return append(dst, msg...), nil
}

// readFrame16 reads a uint16 length-prefixed frame of 1..max bytes.
func readFrame16(r io.Reader, max int, field string) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, readErr(err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, fail(CodeEmpty, field)
	}
	if n > max {
		return nil, fail(CodeTooLarge, field)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, readErr(err)
	}
	return msg, nil
}
