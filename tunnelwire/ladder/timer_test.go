package ladder

import "testing"

func TestTimerFiresInsideWindow(t *testing.T) {
	m := New(0, true)
	m.Step(Event{At: 0, Kind: EvStart})
	o := m.Step(Event{At: 0, Kind: EvDialFailed, Cause: "dial"})
	w := o.Timers[TimerRedial]
	if w != (Window{0, 1000}) {
		t.Fatal(w)
	}
	if o := m.Step(Event{At: 400, Kind: EvTimer, Reason: TimerRedial}); len(o.Actions) != 1 || o.Actions[0] != ActDial {
		t.Fatalf("inside the window: %+v", o)
	}
	if o := m.Step(Event{At: 500, Kind: EvTimer, Reason: TimerRedial}); len(o.Actions) != 0 {
		t.Fatalf("fired twice: %+v", o)
	}
}

func TestTimerBeforeWindowOrUnknown(t *testing.T) {
	m := New(0, true)
	m.Step(Event{At: 0, Kind: EvStart})
	m.Step(Event{At: 0, Kind: EvDialOK})
	m.Step(Event{At: 10, Kind: EvRevoke, Scope: "DEVICE"})
	o := m.Step(Event{At: 20, Kind: EvRefused, Code: "KEY_REVOKED"})
	w, ok := o.Timers[TimerRedial]
	if !ok || w[0] != 20 {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 20, Kind: EvTimer, Reason: TimerProbe}); len(o.Actions) != 0 {
		t.Fatalf("unknown timer fired: %+v", o)
	}
	m2 := New(0, true)
	m2.Step(Event{At: 0, Kind: EvStart})
	m2.Step(Event{At: 5, Kind: EvRefused, Code: "PROTOCOL_DISABLED"})
	if o := m2.Step(Event{At: 6, Kind: EvTimer, Reason: TimerHeartbeat}); len(o.Actions) != 0 {
		t.Fatalf("fired before the window: %+v", o)
	}
	if o := m2.Step(Event{At: 5 + HoldPoll.Milliseconds(), Kind: EvTimer, Reason: TimerHeartbeat}); len(o.Actions) != 1 || o.Actions[0] != ActHeartbeat {
		t.Fatalf("at the window: %+v", o)
	}
}
