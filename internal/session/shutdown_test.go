package session

import (
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func TestStopWithFullEventBuffer(t *testing.T) {
	h := newHarness(t)
	c := h.up(h.dial())
	go func() {
		for {
			select {
			case c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Pong{Pong: &pb.Pong{}}}:
			case <-c.closed:
				return
			}
		}
	}()
	time.Sleep(5 * time.Millisecond)
	h.cancel()
	select {
	case <-h.done:
		h.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return with a busy reader")
	}
}
