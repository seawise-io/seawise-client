package session

import (
	"net/http"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// The stream 0 attempts must not use up the HTTPS heartbeat's budget.
func TestHTTPSHeartbeatHasItsOwnBudget(t *testing.T) {
	oldCall, oldHB := callTimeout, HeartbeatTimeout
	callTimeout, HeartbeatTimeout = 300*time.Millisecond, 250*time.Millisecond
	defer func() { callTimeout, HeartbeatTimeout = oldCall, oldHB }()
	h := newHarness(t)
	h.hb.set(func(n string) (int, string) {
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000001), flagsDoc(t, 2, "off"))
	})
	c := h.up(h.dial())
	c.in <- &pb.ControlMessage{Body: &pb.ControlMessage_Drain{Drain: &pb.Drain{Reason: pb.DrainReason_KILL_SWITCH, Action: pb.DrainAction_HOLD, DeadlineMs: 60000}}}
	h.wait("HTTPS answer applied after unanswered stream 0 calls", func(s Status) bool { return s.Hold == ladder.HoldFlagsOff })
}
