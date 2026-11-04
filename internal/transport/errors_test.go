package transport

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

func TestRefusalKinds(t *testing.T) {
	want := map[pb.RefuseCode]Kind{
		pb.RefuseCode_INVALID_PROOF: Auth, pb.RefuseCode_KEY_REVOKED: Auth, pb.RefuseCode_NOT_ENROLLED: Auth,
		pb.RefuseCode_ACCOUNT_SUSPENDED: Auth, pb.RefuseCode_PROTOCOL_DISABLED: Refused, pb.RefuseCode_VERSION_TOO_OLD: Refused,
		pb.RefuseCode_TOO_MANY_ROUTES: Refused, pb.RefuseCode_EDGE_NOT_READY: Transient, pb.RefuseCode_OVERLOADED: Transient,
		pb.RefuseCode_BAD_REQUEST: Transient,
	}
	for code, kind := range want {
		e := refusal(&pb.HelloRefuse{Code: code, RetryAfterMs: 2000, Detail: "edge text"})
		if e.Kind != kind || e.Code != code || e.RetryAfter != 2*time.Second || e.Cause != "" {
			t.Errorf("%v: %+v", code, e)
		}
		if strings.Contains(e.Error(), "edge text") {
			t.Error("detail surfaced")
		}
		ev, ok := e.Event(5)
		if !ok || ev != (ladder.Event{At: 5, Kind: ladder.EvRefused, Code: code.String()}) {
			t.Errorf("%v: %+v", code, ev)
		}
	}
}

func TestEvents(t *testing.T) {
	for _, cause := range []string{CauseDial, CauseTLS, CauseALPN, CauseSubprotocol, CauseAckSignature} {
		ev, ok := blocked(cause, "x", nil).Event(9)
		if !ok || ev != (ladder.Event{At: 9, Kind: ladder.EvDialFailed, Cause: cause}) {
			t.Error(cause, ev)
		}
	}
	ev, ok := (&Error{Kind: Refused, Cause: CauseEdgeTooOld}).Event(1)
	if !ok || ev.Kind != ladder.EvDialFailed || ev.Cause != CauseEdgeTooOld {
		t.Fatal(ev)
	}
	if _, ok := local("kill_switch", ErrKillSwitch).Event(1); ok {
		t.Fatal("local failure reaches the ladder")
	}
}

func TestErrorText(t *testing.T) {
	e := blocked(CauseTLS, "upgrade", errors.New("boom"))
	if e.Error() != "transport: blocked tls (upgrade): boom" || !errors.Is(e, e.Err) || KindOf(e) != Blocked {
		t.Fatal(e.Error())
	}
	r := refusal(&pb.HelloRefuse{Code: pb.RefuseCode_OVERLOADED})
	if r.Error() != "transport: transient OVERLOADED (hello_refused)" {
		t.Fatal(r.Error())
	}
	if KindOf(nil) != 0 || KindOf(errors.New("x")) != 0 || !errors.Is(local("k", ErrKillSwitch), ErrKillSwitch) {
		t.Fatal("KindOf")
	}
	for k, s := range map[Kind]string{Local: "local", Blocked: "blocked", Transient: "transient", Refused: "refused", Auth: "auth", 0: "unknown"} {
		if k.String() != s {
			t.Error(k, s)
		}
	}
}

func TestRefusalRetryAfterClamped(t *testing.T) {
	e := refusal(&pb.HelloRefuse{Code: pb.RefuseCode_OVERLOADED, RetryAfterMs: 1<<32 - 1})
	if e.RetryAfter != time.Duration(wire.MaxRefuseRetryMs)*time.Millisecond {
		t.Fatal(e.RetryAfter)
	}
}
