package transport

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/caps"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// A message that does not encode is never written and takes no seq, so
// the next message keeps the sequence the edge expects.
func TestRefusedMessageTakesNoSeq(t *testing.T) {
	var out wire.SeqOut
	var buf bytes.Buffer
	bad := &pb.ControlMessage{Body: &pb.ControlMessage_DeviceCall{DeviceCall: &pb.DeviceCall{CallId: 1, IdempotencyKey: []byte("short")}}}
	if err := send(&buf, &out, bad); err == nil || buf.Len() != 0 {
		t.Fatal("invalid message sent", err)
	}
	for want := uint64(1); want <= 2; want++ {
		ping := &pb.ControlMessage{Body: &pb.ControlMessage_Ping{Ping: &pb.Ping{Nonce: want}}}
		if err := send(&buf, &out, ping); err != nil {
			t.Fatal(err)
		}
		if ping.Seq != want {
			t.Fatalf("seq %d, want %d", ping.Seq, want)
		}
	}
	rd := wire.NewControlReader(&buf, nil)
	for want := uint64(1); want <= 2; want++ {
		b, err := rd.Next()
		if err != nil {
			t.Fatal(err)
		}
		m, err := wire.DecodeControl(b, wire.FromAgent)
		if err != nil || m.GetSeq() != want {
			t.Fatal(m, err)
		}
	}
}

// The stream deadline and the Hello timer are one deadline: whichever
// fires first, the dial fails as hello_deadline.
func TestHelloDeadlineWhenTheStreamDeadlineFiresFirst(t *testing.T) {
	for _, c := range []Carriage{TLS, WebSocket} {
		e := newEdge(t)
		e.hang = true
		skew := func(cfg *Config) {
			// The I/O deadlines come from Now, the timer from the real clock.
			cfg.Now = func() time.Time { return time.Now().Add(-caps.HelloDeadline + 500*time.Millisecond) }
		}
		start := time.Now()
		_, err := e.dialer(t, skew).Dial(ctx(t), testName, c)
		er := asError(t, err)
		if er.Kind != Blocked || er.Reason != "hello_deadline" || er.Cause != CauseAckSignature {
			t.Fatal(c, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatal(c, "waited for the timer", d)
		}
	}
}

// A deadline error counts at any time; any other error only once the
// Hello deadline has passed, so a peer's text ending in "i/o timeout" does
// not count early.
func TestHelloTimedOut(t *testing.T) {
	deadline := time.Unix(1_700_000_000, 0)
	text := errors.New("stream reset: connection closed: read tcp 127.0.0.1:1->127.0.0.1:2: i/o timeout")
	for _, c := range []struct {
		err  error
		now  time.Time
		want bool
	}{
		{nil, deadline.Add(time.Second), false},
		{os.ErrDeadlineExceeded, deadline.Add(-time.Second), true},
		{fmt.Errorf("ack: %w", os.ErrDeadlineExceeded), deadline.Add(-time.Second), true},
		{text, deadline.Add(-time.Millisecond), false},
		{text, deadline, true},
		{errors.New("stream reset: connection closed: EOF"), deadline.Add(time.Second), true},
		{errors.New("stream reset: connection closed: EOF"), deadline.Add(-time.Second), false},
	} {
		if got := helloTimedOut(c.err, deadline, c.now); got != c.want {
			t.Errorf("helloTimedOut(%v, now-deadline=%v) = %v, want %v", c.err, c.now.Sub(deadline), got, c.want)
		}
	}
}
