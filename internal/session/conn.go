package session

import (
	"context"
	"time"

	"github.com/libp2p/go-yamux/v5"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/transport"
)

// Conn is one verified session: HelloAck checked, stream 0 open.
type Conn interface {
	Send(*pb.ControlMessage) error
	Next() (*pb.ControlMessage, error)
	Close() error
	// LastReceived is when the last byte arrived on the session.
	LastReceived() time.Time
	Info() ConnInfo
}

// ConnInfo describes a session.
type ConnInfo struct {
	Carriage     transport.Carriage
	EdgeID       string
	SessionID    []byte
	TimeNonce    []byte // Hello.time_nonce, bound into the RouteSet's signed time
	PingInterval time.Duration
	PingTimeout  time.Duration
	Proxied      bool
	LastKnown    bool
	Mux          *yamux.Session // data streams arrive here
}

// DialFunc opens a session to the tunnel name over a carriage. Errors are
// *transport.Error where the ladder must see them.
type DialFunc func(ctx context.Context, name string, c transport.Carriage) (Conn, error)

type transportConn struct{ *transport.Session }

func (c transportConn) Info() ConnInfo {
	acc := c.Accepted
	return ConnInfo{
		Carriage: c.Carriage, EdgeID: acc.Ack.GetEdgeId(), SessionID: acc.Ack.GetSessionId(),
		TimeNonce: c.Hello.GetTimeNonce(), PingInterval: acc.PingInterval, PingTimeout: acc.PingTimeout,
		Proxied: c.Proxied, LastKnown: c.LastKnown, Mux: c.Mux,
	}
}

// FromTransport adapts a dialer factory: the dialer is built for every dial,
// so a rotated device key or a new key set takes effect at the next Hello.
func FromTransport(newDialer func() (*transport.Dialer, error)) DialFunc {
	return func(ctx context.Context, name string, c transport.Carriage) (Conn, error) {
		d, err := newDialer()
		if err != nil {
			return nil, err
		}
		s, err := d.Dial(ctx, name, c)
		if err != nil {
			return nil, err
		}
		return transportConn{s}, nil
	}
}
