package ladder

import (
	"slices"
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	want := []int64{900000, 1800000, 3600000, 7200000, 14400000, 14400000, 14400000}
	for i, w := range want {
		if got := backoff(ReprobeBase, ReprobeCap, i); got != w {
			t.Errorf("level %d: %d", i, got)
		}
	}
	if backoff(RedialBase, RedialCap, 0) != 1000 || backoff(RedialBase, RedialCap, 4) != 16000 || backoff(RedialBase, RedialCap, 5) != 30000 || backoff(RedialBase, RedialCap, 60) != 30000 {
		t.Fatal("redial")
	}
	if backoff(10*time.Second, 25*time.Second, 1) != 20000 || backoff(10*time.Second, 25*time.Second, 2) != 25000 {
		t.Fatal("cap between doublings")
	}
}

func TestSetPing(t *testing.T) {
	m := New(Own, 1, true)
	m.SetPing(10*time.Second, 20*time.Second)
	m.Step(Event{At: 0, Kind: EvReceived})
	if o := m.Step(Event{At: 9999, Kind: EvTick}); len(o.Actions) != 0 {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 10000, Kind: EvTick}); !slices.Equal(o.Actions, []string{ActSendPing}) {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 29999, Kind: EvTick}); o.State != Own {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 30000, Kind: EvTick}); o.State != OwnReconnecting || m.State() != OwnReconnecting {
		t.Fatal(o)
	}
}

func TestIgnoredEvents(t *testing.T) {
	for _, st := range []string{FRPC, Hold, V1} {
		m := New(st, 1, true)
		if o := m.Step(Event{Kind: EvDialOK}); o.State != st || !slices.Equal(o.Actions, []string{ActCloseSession}) {
			t.Errorf("%s dial_ok: %v", st, o)
		}
		for _, e := range []Event{{Kind: EvSessionLost}, {Kind: EvDrain, Reason: "ROLLOUT"}, {Kind: EvRevoke, Scope: "DEVICE"}, {Kind: EvNetwork}, {Kind: EvDialFailed, Cause: "dial"}} {
			if o := m.Step(e); o.State != st || len(o.Actions) != 0 {
				t.Errorf("%s %s: %v", st, e.Kind, o)
			}
		}
	}
	m := New(V1, 0, false)
	if o := m.Step(Event{Kind: EvRepair}); o.State != V1 {
		t.Fatal(o)
	}
	if o := m.Step(Event{Kind: EvSignedState, DeviceStatus: "revoked", AccountStatus: "active"}); o.State != V1 {
		t.Fatal("V1 moved to HOLD", o)
	}
	m = New(Hold, 0, false)
	if o := m.Step(Event{Kind: EvFRPCRefused, Authenticated: true}); o.State != Hold || len(o.Actions) != 0 {
		t.Fatal(o)
	}
}

func TestOwnDialOKWithoutSecondCloses(t *testing.T) {
	m := New(Own, 1, true)
	if o := m.Step(Event{Kind: EvDialOK}); !slices.Equal(o.Actions, []string{ActCloseSession}) {
		t.Fatal(o)
	}
	m.Step(Event{Kind: EvDrain, Reason: "ROLLOUT", Action: "RECONNECT"})
	if o := m.Step(Event{Kind: EvDrain, Reason: "MAX_AGE", Action: "RECONNECT"}); len(o.Actions) != 0 {
		t.Fatal("second drain dialled again", o)
	}
	if o := m.Step(Event{Kind: EvRevoke, Scope: "REVOKE_UNSPECIFIED"}); len(o.Actions) != 0 || o.State != Own {
		t.Fatal(o)
	}
}

func TestFlagsInEveryState(t *testing.T) {
	m := New(Probing, 1, true)
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "OFF"}); o.State != FRPC || len(o.Actions) != 0 {
		t.Fatal(o)
	}
	m = New(OwnReconnecting, 1, true)
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "OFF"}); o.State != FRPC || !slices.Equal(o.Actions, []string{ActStartFRPC}) {
		t.Fatal(o)
	}
	m = New(Own, 1, true)
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "ON"}); o.State != Own {
		t.Fatal(o)
	}
	m = New(FRPC, 1, true)
	m.Step(Event{At: 0, Kind: EvRefused, Code: "OVERLOADED"})
	m.state = FRPC
	m.set(TimerProbe, 0, 10)
	if o := m.Step(Event{At: 5, Kind: EvFlags, Generation: 2, Mode: "OFF"}); len(o.Timers) != 0 {
		t.Fatal("probe kept after OFF", o)
	}
	m = New(FRPC, 1, false)
	m.set(TimerProbe, 0, 10)
	if o := m.Step(Event{At: 10, Kind: EvTick}); o.State != FRPC || len(o.Actions) != 0 {
		t.Fatal("probe while OFF", o)
	}
	m = New(Hold, 1, false)
	if o := m.Step(Event{Kind: EvSignedState, DeviceStatus: "active", AccountStatus: "active"}); o.State != FRPC {
		t.Fatal("hold not cleared", o)
	}
	m = New(Probing, 1, true)
	if o := m.Step(Event{At: 1, Kind: EvSessionLost}); o.State != FRPC || o.Timers[TimerProbe] != (Window{1, 900001}) {
		t.Fatal(o)
	}
}

func TestDrainUseFRPCWhenOff(t *testing.T) {
	m := New(Own, 1, false)
	o := m.Step(Event{Kind: EvDrain, Reason: "KILL_SWITCH", Action: "USE_FRPC"})
	if o.State != FRPC || !slices.Equal(o.Actions, []string{ActStartFRPC, ActCloseAfterFRPC}) {
		t.Fatal(o)
	}
}

func TestEnrolledDeletesOnce(t *testing.T) {
	m := New(FRPC, 0, false)
	if o := m.Step(Event{Kind: EvEnrolled}); !slices.Equal(o.Actions, []string{ActDeleteV1Copy}) {
		t.Fatal(o)
	}
	if o := m.Step(Event{Kind: EvEnrolled}); len(o.Actions) != 0 {
		t.Fatal(o)
	}
}

func TestOutputIsACopy(t *testing.T) {
	m := New(FRPC, 0, false)
	o := m.Step(Event{Kind: EvFlags, Generation: 1, Mode: "ON"})
	o.Timers["x"] = Window{}
	if _, ok := m.timers["x"]; ok {
		t.Fatal("output aliases the machine")
	}
}
