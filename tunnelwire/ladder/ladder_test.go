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

const hourMs = int64(time.Hour / time.Millisecond)

// started returns a machine with a TLS session up at t=0.
func started() *Machine {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvDialOK})
	return m
}

// onWebSocket returns a machine with a WebSocket session up at t=0.
func onWebSocket() *Machine {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvDialFailed, Cause: "tls"})
	m.Step(Event{Kind: EvDialFailed, Cause: "tls"})
	m.Step(Event{Kind: EvDialOK})
	return m
}

func TestStart(t *testing.T) {
	m := New(0, true)
	if m.State() != Own {
		t.Fatal(m.State())
	}
	if o := m.Step(Event{Kind: EvStart}); o.State != Own || o.Transport != TLS || !slices.Equal(o.Actions, []string{ActDial}) {
		t.Fatal(o)
	}
	m = New(3, false)
	o := m.Step(Event{At: 5, Kind: EvStart})
	if o.State != Hold || o.Hold != HoldFlagsOff || o.Timers[TimerHeartbeat] != (Window{300005, 300005}) || o.Timers[TimerRedial] != (Window{}) {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 6, Kind: EvDialOK}); o.State != Hold || !slices.Equal(o.Actions, []string{ActCloseSession}) {
		t.Fatal("hold accepted a session", o)
	}
}

func TestSetPing(t *testing.T) {
	m := started()
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
	if o := m.Step(Event{At: 30000, Kind: EvTick}); o.State != Reconnecting || !slices.Equal(o.Actions, []string{ActDial}) {
		t.Fatal(o)
	}
}

func TestNoLivenessWithoutSession(t *testing.T) {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	if o := m.Step(Event{At: hourMs, Kind: EvTick}); len(o.Actions) != 0 {
		t.Fatal("pinged before a session", o)
	}
}

func TestCarriageFlipsAfterTwoFailures(t *testing.T) {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	if o := m.Step(Event{At: 1, Kind: EvDialFailed, Cause: "tls"}); o.State != Reconnecting || o.Transport != TLS || o.Timers[TimerRedial] != (Window{1, 1001}) {
		t.Fatal(o)
	}
	m.Step(Event{At: 1001, Kind: EvTick})
	if o := m.Step(Event{At: 1002, Kind: EvDialFailed, Cause: "dial"}); o.Transport != WebSocket || o.Timers[TimerRedial] != (Window{1002, 3002}) {
		t.Fatal(o)
	}
	m.Step(Event{At: 3002, Kind: EvTick})
	o := m.Step(Event{At: 3003, Kind: EvDialOK})
	if o.State != OwnWS || o.Transport != WebSocket || o.Timers[TimerProbe] != (Window{3003, 903003}) {
		t.Fatal(o)
	}
}

func TestRefusalDoesNotFlipCarriage(t *testing.T) {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	for i := int64(1); i <= 4; i++ {
		if o := m.Step(Event{At: i, Kind: EvRefused, Code: "OVERLOADED"}); o.Transport != TLS || o.State != Reconnecting {
			t.Fatal(i, o)
		}
	}
}

// Only subprotocol refusals, which arrive inside the verified TLS session,
// count toward update_required; two with no session between are needed.
func TestNoMajorOnBothCarriagesIsUpdateRequired(t *testing.T) {
	m := onWebSocketDialling()
	if o := m.Step(Event{At: 3, Kind: EvDialFailed, Cause: "subprotocol"}); o.State != Reconnecting {
		t.Fatal("one subprotocol refusal held", o)
	}
	m.Step(Event{At: 4, Kind: EvDialFailed, Cause: "dial"})
	m.Step(Event{At: 5, Kind: EvDialFailed, Cause: "alpn"})
	m.Step(Event{At: 6, Kind: EvDialFailed, Cause: "alpn"})
	o := m.Step(Event{At: 7, Kind: EvDialFailed, Cause: "subprotocol"})
	if o.State != Hold || o.Hold != HoldUpdate || o.Timers[TimerRedial] != (Window{7, 900007}) {
		t.Fatal(o)
	}
	m.Step(Event{At: 900007, Kind: EvTick})
	m.Step(Event{At: 900008, Kind: EvDialFailed, Cause: "tls"})
	m.Step(Event{At: 900009, Kind: EvDialFailed, Cause: "tls"})
	if o := m.Step(Event{At: 900010, Kind: EvDialFailed, Cause: "subprotocol"}); o.State != Reconnecting {
		t.Fatal("hold redial kept the refusal count", o)
	}
	m = onWebSocketDialling()
	m.Step(Event{At: 3, Kind: EvDialFailed, Cause: "subprotocol"})
	if o := m.Step(Event{At: 4, Kind: EvNetwork}); o.Transport != TLS || !slices.Equal(o.Actions, []string{ActDial}) || o.Timers[TimerRedial] != (Window{}) {
		t.Fatal(o)
	}
	m.Step(Event{At: 5, Kind: EvDialFailed, Cause: "dial"})
	if o := m.Step(Event{At: 6, Kind: EvDialFailed, Cause: "dial"}); o.Transport != WebSocket {
		t.Fatal("network change kept the failure count", o)
	}
	if o := m.Step(Event{At: 7, Kind: EvDialFailed, Cause: "subprotocol"}); o.State != Reconnecting {
		t.Fatal("network change kept the refusal count", o)
	}
	m = onWebSocketDialling()
	m.Step(Event{At: 3, Kind: EvDialFailed, Cause: "subprotocol"})
	m.Step(Event{At: 4, Kind: EvDialOK})
	m.Step(Event{At: 5, Kind: EvSessionLost})
	if o := m.Step(Event{At: 6, Kind: EvDialFailed, Cause: "subprotocol"}); o.State != Reconnecting {
		t.Fatal("a session kept the refusal count", o)
	}
}

// onWebSocketDialling returns a machine whose next dial uses WebSocket
// after two TLS failures.
func onWebSocketDialling() *Machine {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{At: 1, Kind: EvDialFailed, Cause: "tls"})
	m.Step(Event{At: 2, Kind: EvDialFailed, Cause: "tls"})
	return m
}

// Forged plaintext alerts reach the agent before the certificate is
// verified; however many arrive on either carriage, they never hold it,
// and it reconnects as soon as they stop.
func TestForgedAlertsNeverHold(t *testing.T) {
	m := started()
	m.Step(Event{At: 0, Kind: EvSessionLost})
	at := int64(0)
	for i := 0; i < 40; i++ {
		o := m.Step(Event{At: at, Kind: EvDialFailed, Cause: "alpn"})
		w := o.Timers[TimerRedial]
		if o.State != Reconnecting || o.Hold != "" || w[1]-w[0] > 30000 {
			t.Fatal(i, o)
		}
		at = w[1]
		m.Step(Event{At: at, Kind: EvTick})
	}
	if o := m.Step(Event{At: at, Kind: EvDialOK}); o.State != Own && o.State != OwnWS {
		t.Fatal("did not recover", o)
	}
}

func TestUnsignedHoldsRedial(t *testing.T) {
	for code, reason := range map[string]string{"VERSION_TOO_OLD": HoldUpdate, "PROTOCOL_DISABLED": HoldMaintenance, "TOO_MANY_ROUTES": HoldTooManyRoutes} {
		m := New(1, true)
		m.Step(Event{Kind: EvStart})
		o := m.Step(Event{At: 10, Kind: EvRefused, Code: code})
		if o.State != Hold || o.Hold != reason || !slices.Equal(o.Actions, []string{ActStopTunnels, ActHeartbeat}) || o.Timers[TimerRedial] != (Window{10, 900010}) || o.Timers[TimerHeartbeat] != (Window{300010, 300010}) {
			t.Fatal(code, o)
		}
		if o := m.Step(Event{At: 900010, Kind: EvTick}); o.State != Reconnecting || o.Hold != "" || o.Transport != TLS || !slices.Equal(o.Actions, []string{ActDial}) || len(o.Timers) != 0 {
			t.Fatal(code, o)
		}
		if o := m.Step(Event{At: 900011, Kind: EvRefused, Code: code}); o.Timers[TimerRedial] != (Window{900011, 2700011}) {
			t.Fatal(code, "not doubled", o)
		}
		m.Step(Event{At: 2700011, Kind: EvTick})
		m.Step(Event{At: 2700012, Kind: EvDialOK})
		if o := m.Step(Event{At: 2700013, Kind: EvSessionLost}); o.State != Reconnecting {
			t.Fatal(o)
		}
		if o := m.Step(Event{At: 2700014, Kind: EvRefused, Code: code}); o.Timers[TimerRedial] != (Window{2700014, 3600014}) {
			t.Fatal(code, "slow level not reset by a session", o)
		}
	}
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	if o := m.Step(Event{At: 1, Kind: EvDialFailed, Cause: "edge_too_old"}); o.Hold != HoldUpdate {
		t.Fatal(o)
	}
}

func TestAuthRefusalRedialsSlowly(t *testing.T) {
	for _, code := range []string{"KEY_REVOKED", "ACCOUNT_SUSPENDED", "INVALID_PROOF", "NOT_ENROLLED"} {
		m := New(1, true)
		m.Step(Event{Kind: EvStart})
		o := m.Step(Event{At: 1, Kind: EvRefused, Code: code})
		if o.State != Reconnecting || o.Transport != TLS || !slices.Equal(o.Actions, []string{ActHeartbeat}) || o.Timers[TimerRedial] != (Window{1, 900001}) {
			t.Fatal(code, o)
		}
		m.Step(Event{At: 900001, Kind: EvTick})
		if o := m.Step(Event{At: 900002, Kind: EvRefused, Code: code}); o.State != Reconnecting || o.Timers[TimerRedial] != (Window{900002, 2700002}) {
			t.Fatal(code, o)
		}
	}
}

func TestTransientRefusalBacksOff(t *testing.T) {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	want := []Window{{0, 1000}, {0, 2000}, {0, 4000}}
	for i, w := range want {
		if o := m.Step(Event{Kind: EvRefused, Code: "EDGE_NOT_READY"}); o.Timers[TimerRedial] != w || len(o.Actions) != 0 {
			t.Fatal(i, o)
		}
	}
}

func TestSecondDialFailureKeepsSession(t *testing.T) {
	m := started()
	m.Step(Event{At: 1, Kind: EvDrain, Reason: "ROLLOUT", Action: "RECONNECT"})
	if o := m.Step(Event{At: 2, Kind: EvRefused, Code: "VERSION_TOO_OLD"}); o.State != Own || len(o.Actions) != 0 || len(o.Timers) != 0 {
		t.Fatal(o)
	}
	for _, e := range []Event{{At: 3, Kind: EvRefused, Code: "KEY_REVOKED"}, {At: 4, Kind: EvDialFailed, Cause: "dial"}} {
		if o := m.Step(e); o.State != Own || len(o.Actions) != 0 || len(o.Timers) != 0 {
			t.Fatal(e, o)
		}
	}
	if o := m.Step(Event{At: 5, Kind: EvDrain, Reason: "ROLLOUT", Action: "RECONNECT"}); !slices.Equal(o.Actions, []string{ActDialSecond}) {
		t.Fatal("failed second dial still counted as in flight", o)
	}
}

func TestWebSocketReprobe(t *testing.T) {
	m := onWebSocket()
	o := m.Step(Event{At: 900000, Kind: EvTick})
	if o.State != OwnWS || !slices.Equal(o.Actions, []string{ActDialSecond, ActSendPing}) || o.Transport != WebSocket {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 900000, Kind: EvDrain, Reason: "ROLLOUT", Action: "RECONNECT"}); len(o.Actions) != 0 {
		t.Fatal("dialled twice", o)
	}
	o = m.Step(Event{At: 900001, Kind: EvDialFailed, Cause: "tls"})
	if o.State != OwnWS || o.Timers[TimerProbe] != (Window{900001, 2700001}) {
		t.Fatal(o)
	}
	m.Step(Event{At: 900002, Kind: EvReceived})
	m.Step(Event{At: 2700001, Kind: EvTick})
	o = m.Step(Event{At: 2700002, Kind: EvDialOK})
	if o.State != Own || o.Transport != TLS || !slices.Equal(o.Actions, []string{ActSwitchSession}) || len(o.Timers) != 0 {
		t.Fatal(o)
	}
	m.Step(Event{At: 2700003, Kind: EvSessionLost})
	m.Step(Event{At: 2700004, Kind: EvDialFailed, Cause: "tls"})
	m.Step(Event{At: 2700005, Kind: EvDialFailed, Cause: "tls"})
	if o := m.Step(Event{At: 2700006, Kind: EvDialOK}); o.Timers[TimerProbe] != (Window{2700006, 3600006}) {
		t.Fatal("probe level not reset by a TLS session", o)
	}
}

func TestReprobeNotWhileSecondDial(t *testing.T) {
	m := onWebSocket()
	m.Step(Event{At: 1, Kind: EvDrain, Reason: "ROLLOUT", Action: "RECONNECT"})
	if o := m.Step(Event{At: 900000, Kind: EvTick}); !slices.Equal(o.Actions, []string{ActSendPing}) {
		t.Fatal(o)
	}
}

func TestDrainOnWebSocketKeepsCarriage(t *testing.T) {
	m := onWebSocket()
	m.Step(Event{Kind: EvDrain, Reason: "MAX_AGE", Action: "RECONNECT"})
	if o := m.Step(Event{Kind: EvDialOK}); o.State != OwnWS || o.Transport != WebSocket || o.Timers[TimerProbe] != (Window{0, 900000}) {
		t.Fatal(o)
	}
}

func TestSessionLostDuringSecondDial(t *testing.T) {
	m := onWebSocket()
	m.Step(Event{At: 900000, Kind: EvTick})
	o := m.Step(Event{At: 900001, Kind: EvSessionLost})
	if o.State != Reconnecting || o.Transport != TLS || len(o.Actions) != 0 || len(o.Timers) != 0 {
		t.Fatal("in-flight dial not reused", o)
	}
	if o := m.Step(Event{At: 900002, Kind: EvDialOK}); o.State != Own || len(o.Actions) != 0 {
		t.Fatal(o)
	}
}

func TestDrainHold(t *testing.T) {
	m := started()
	o := m.Step(Event{At: 50, Kind: EvDrain, Reason: "KILL_SWITCH", Action: "HOLD"})
	if o.State != Own || !slices.Equal(o.Actions, []string{ActHeartbeat, ActDialSecond}) {
		t.Fatal("unsigned hold obeyed", o)
	}
	m = started()
	o = m.Step(Event{At: 50, Kind: EvDrain, Reason: "SUPERSEDED", Action: "HOLD"})
	if o.State != Reconnecting || !slices.Equal(o.Actions, []string{ActCloseSession, ActCountSupersede}) || o.Timers[TimerRedial] != (Window{60050, 60050}) {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 60050, Kind: EvTick}); !slices.Equal(o.Actions, []string{ActDial}) {
		t.Fatal(o)
	}
	m = started()
	if o := m.Step(Event{At: 50, Kind: EvDrain, Reason: "SUPERSEDED", Action: "RECONNECT"}); o.State != Own || !slices.Equal(o.Actions, []string{ActDialSecond}) {
		t.Fatal(o)
	}
}

func TestFlagsInEveryState(t *testing.T) {
	m := started()
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "ON"}); o.State != Own || len(o.Actions) != 0 {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 7, Kind: EvFlags, Generation: 3, Mode: "OFF"}); o.State != Hold || o.Hold != HoldFlagsOff || !slices.Equal(o.Actions, []string{ActStopTunnels}) {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 8, Kind: EvFlags, Generation: 4, Mode: "ON"}); o.State != Reconnecting || o.Hold != "" || o.Timers[TimerDial] != (Window{8, 30008}) || len(o.Timers) != 1 || len(o.Actions) != 0 {
		t.Fatal(o)
	}
	if o := m.Step(Event{At: 30008, Kind: EvTick}); !slices.Equal(o.Actions, []string{ActDial}) {
		t.Fatal(o)
	}
	m = New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvSignedState, DeviceStatus: "revoked", AccountStatus: "active"})
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "OFF"}); o.Hold != HoldRevoked {
		t.Fatal("flags replaced a signed revocation", o)
	}
	if o := m.Step(Event{Kind: EvSignedState, DeviceStatus: "active", AccountStatus: "active"}); o.Hold != HoldFlagsOff {
		t.Fatal(o)
	}
	m = New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvRefused, Code: "PROTOCOL_DISABLED"})
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "OFF"}); o.Hold != HoldFlagsOff || o.Timers[TimerRedial] != (Window{}) {
		t.Fatal(o)
	}
	m = New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvRefused, Code: "PROTOCOL_DISABLED"})
	if o := m.Step(Event{At: 9, Kind: EvFlags, Generation: 2, Mode: "ON"}); o.State != Reconnecting || o.Timers[TimerDial] != (Window{9, 30009}) {
		t.Fatal(o)
	}
	m = New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvRepair})
	if o := m.Step(Event{Kind: EvFlags, Generation: 2, Mode: "ON"}); o.State != Hold || o.Hold != HoldRepair {
		t.Fatal("flags cleared a repair hold", o)
	}
	m = New(1, true)
	m.Step(Event{Kind: EvStart})
	if o := m.Step(Event{Kind: EvFlags, Generation: 1, Mode: "OFF"}); o.State != Own || !slices.Equal(o.Actions, []string{ActFlagsRollback}) {
		t.Fatal(o)
	}
}

func TestSignedStateClears(t *testing.T) {
	for _, st := range [][2]string{{"revoked", "active"}, {"compromised", "active"}, {"active", "suspended"}, {"active", "banned"}} {
		m := started()
		o := m.Step(Event{At: 1, Kind: EvSignedState, DeviceStatus: st[0], AccountStatus: st[1]})
		want := HoldRevoked
		if st[0] == "active" {
			want = HoldSuspended
		}
		if o.State != Hold || o.Hold != want || o.Timers[TimerRedial] != (Window{}) {
			t.Fatal(st, o)
		}
		if o := m.Step(Event{At: 2, Kind: EvSignedState, DeviceStatus: "pending", AccountStatus: "active"}); o.State != Hold {
			t.Fatal(st, o)
		}
		if o := m.Step(Event{At: 3, Kind: EvSignedState, DeviceStatus: "active", AccountStatus: "active"}); o.State != Reconnecting || o.Timers[TimerDial] != (Window{3, 30003}) {
			t.Fatal(st, o)
		}
	}
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvRefused, Code: "VERSION_TOO_OLD"})
	if o := m.Step(Event{Kind: EvSignedState, DeviceStatus: "active", AccountStatus: "active"}); o.Hold != HoldUpdate {
		t.Fatal("signed state cleared an update hold", o)
	}
	m = started()
	if o := m.Step(Event{Kind: EvSignedState, DeviceStatus: "active", AccountStatus: "active"}); o.State != Own || len(o.Actions) != 0 {
		t.Fatal(o)
	}
	m = New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvRepair})
	if o := m.Step(Event{Kind: EvSignedState, DeviceStatus: "active", AccountStatus: "active"}); o.State != Reconnecting {
		t.Fatal("repair hold not cleared", o)
	}
}

func TestIgnoredEvents(t *testing.T) {
	m := New(1, true)
	m.Step(Event{Kind: EvStart})
	m.Step(Event{Kind: EvRepair})
	for _, e := range []Event{{Kind: EvSessionLost}, {Kind: EvDrain, Reason: "ROLLOUT"}, {Kind: EvRevoke, Scope: "DEVICE"}, {Kind: EvNetwork}, {Kind: EvDialFailed, Cause: "dial"}, {Kind: EvRefused, Code: "PROTOCOL_DISABLED"}} {
		if o := m.Step(e); o.State != Hold || o.Hold != HoldRepair || len(o.Actions) != 0 {
			t.Errorf("%s: %v", e.Kind, o)
		}
	}
	m = started()
	for _, e := range []Event{{Kind: EvDialFailed, Cause: "dial"}, {Kind: EvRefused, Code: "PROTOCOL_DISABLED"}, {Kind: EvNetwork}} {
		if o := m.Step(e); o.State != Own || len(o.Actions) != 0 {
			t.Errorf("%s: %v", e.Kind, o)
		}
	}
}

func TestOwnDialOKWithoutSecondCloses(t *testing.T) {
	m := started()
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

func TestReconnectNeverGivesUp(t *testing.T) {
	m := started()
	m.Step(Event{At: 0, Kind: EvSessionLost})
	at := int64(0)
	for i := 0; i < 50; i++ {
		o := m.Step(Event{At: at, Kind: EvDialFailed, Cause: "dial"})
		w := o.Timers[TimerRedial]
		if o.State != Reconnecting || w[1]-w[0] > 30000 || w[0] != at {
			t.Fatal(i, o)
		}
		at = w[1]
		if o := m.Step(Event{At: at, Kind: EvTick}); !slices.Equal(o.Actions, []string{ActDial}) {
			t.Fatal(i, o)
		}
	}
}

func TestOutputIsACopy(t *testing.T) {
	m := New(0, true)
	o := m.Step(Event{Kind: EvStart})
	o.Timers["x"] = Window{}
	if _, ok := m.timers["x"]; ok {
		t.Fatal("output aliases the machine")
	}
}
