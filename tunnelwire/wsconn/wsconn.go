// Package wsconn carries the yamux byte stream over WebSocket messages for
// the fallback transport. Message boundaries carry no meaning; a text
// message is a protocol error and a message over 1 MiB is refused. It wraps
// any WebSocket library through MessageConn; set the library's own read
// limit to wire.MaxWebSocketMsg as well so it refuses before allocating.
package wsconn

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// MessageConn is the part of a WebSocket connection wsconn needs.
type MessageConn interface {
	// NextReader returns the next data message and whether it is binary.
	NextReader() (binary bool, r io.Reader, err error)
	// WriteBinary sends one binary message.
	WriteBinary(p []byte) error
	Close() error
}

// Errors.
var (
	ErrTextMessage = errors.New("tunnelwire: text message on the tunnel")
	ErrTooLarge    = errors.New("tunnelwire: websocket message over 1 MiB")
)

// Conn is a byte stream over binary WebSocket messages.
type Conn struct {
	mc   MessageConn
	cur  io.Reader
	used int64
	err  error
}

// New wraps mc.
func New(mc MessageConn) *Conn { return &Conn{mc: mc} }

// Read reads the concatenated payloads of binary messages.
func (c *Conn) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	for len(p) > 0 {
		if c.cur == nil {
			bin, r, err := c.mc.NextReader()
			if err != nil {
				c.err = err
				return 0, err
			}
			if !bin {
				c.err = ErrTextMessage
				return 0, c.err
			}
			c.cur, c.used = r, 0
		}
		n, err := c.cur.Read(p)
		c.used += int64(n)
		if c.used > wire.MaxWebSocketMsg {
			c.err = ErrTooLarge
			return 0, c.err
		}
		if err == io.EOF {
			c.cur = nil
			if n == 0 {
				continue
			}
			return n, nil
		}
		if err != nil {
			c.err = err
			return n, err
		}
		if n > 0 {
			return n, nil
		}
	}
	return 0, nil
}

// Write sends p as binary messages of at most 1 MiB.
func (c *Conn) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		n := min(len(p)-done, wire.MaxWebSocketMsg)
		if err := c.mc.WriteBinary(p[done : done+n]); err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

// Close closes the WebSocket connection.
func (c *Conn) Close() error { return c.mc.Close() }

// NetConn adapts Conn to net.Conn for yamux. Deadlines and addresses
// are those of Under, the connection the WebSocket frames travel on:
// go-yamux sets a write deadline before its writes and ends the session
// if that fails. Under is required: without it the deadline setters
// return ErrNoUnder and the addresses are nil.
type NetConn struct {
	*Conn
	Under net.Conn
}

// ErrNoUnder is returned by the deadline setters of a NetConn without Under.
var ErrNoUnder = errors.New("tunnelwire: NetConn has no underlying connection")

func (c NetConn) LocalAddr() net.Addr {
	if c.Under == nil {
		return nil
	}
	return c.Under.LocalAddr()
}

func (c NetConn) RemoteAddr() net.Addr {
	if c.Under == nil {
		return nil
	}
	return c.Under.RemoteAddr()
}

func (c NetConn) SetDeadline(t time.Time) error {
	if c.Under == nil {
		return ErrNoUnder
	}
	return c.Under.SetDeadline(t)
}

func (c NetConn) SetReadDeadline(t time.Time) error {
	if c.Under == nil {
		return ErrNoUnder
	}
	return c.Under.SetReadDeadline(t)
}

func (c NetConn) SetWriteDeadline(t time.Time) error {
	if c.Under == nil {
		return ErrNoUnder
	}
	return c.Under.SetWriteDeadline(t)
}
