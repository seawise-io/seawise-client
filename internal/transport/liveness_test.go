package transport

import (
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func TestLastReceivedAdvancesOnBytes(t *testing.T) {
	for _, c := range []Carriage{TLS, WebSocket} {
		t.Run(c.String(), func(t *testing.T) {
			e := newEdge(t)
			s, err := e.dialer(t).Dial(ctx(t), testName, c)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			first := s.LastReceived()
			if first.IsZero() {
				t.Fatal("no receive time after HelloAck")
			}
			time.Sleep(5 * time.Millisecond)
			if !s.LastReceived().Equal(first) {
				t.Fatal("moved without bytes")
			}
			if err := s.Send(&pb.ControlMessage{Body: &pb.ControlMessage_Ping{Ping: &pb.Ping{Nonce: 1}}}); err != nil {
				t.Fatal(err)
			}
			_, _ = s.Next()
			if !s.LastReceived().After(first) {
				t.Fatal("echoed bytes did not count")
			}
		})
	}
}

func TestLastReceivedZeroWithoutConn(t *testing.T) {
	if !(&Session{}).LastReceived().IsZero() {
		t.Fatal("want zero")
	}
}
