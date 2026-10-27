package ladder

import (
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

type initial struct {
	Generation int64 `json:"generation"`
	ModeOn     bool  `json:"mode_on"`
}

type step struct {
	Event Event  `json:"event"`
	Want  Output `json:"want"`
}

type lcase struct {
	Name    string  `json:"name"`
	Initial initial `json:"initial"`
	Steps   []step  `json:"steps"`
}

type lfile struct {
	Format string  `json:"format"`
	Note   string  `json:"note"`
	Cases  []lcase `json:"cases"`
}

const (
	sec    = int64(1000)
	minute = 60 * sec
	hr     = 60 * minute
)

func run(name string, in initial, events ...Event) lcase {
	m := New(in.Generation, in.ModeOn)
	c := lcase{Name: name, Initial: in}
	for _, e := range events {
		c.Steps = append(c.Steps, step{Event: e, Want: m.Step(e)})
	}
	return c
}

func ev(at int64, kind string) Event { return Event{At: at, Kind: kind} }

func flags(at, gen int64, mode string) Event {
	return Event{At: at, Kind: EvFlags, Generation: gen, Mode: mode}
}

func refused(at int64, code string) Event { return Event{At: at, Kind: EvRefused, Code: code} }

func dialFailed(at int64, cause string) Event { return Event{At: at, Kind: EvDialFailed, Cause: cause} }

func drain(at int64, reason, action string, pending bool) Event {
	return Event{At: at, Kind: EvDrain, Reason: reason, Action: action, PendingKey: pending}
}

func revoke(at int64, scope string) Event { return Event{At: at, Kind: EvRevoke, Scope: scope} }

func state(at int64, dev, acct string) Event {
	return Event{At: at, Kind: EvSignedState, DeviceStatus: dev, AccountStatus: acct}
}

var (
	fresh = initial{ModeOn: true}
	off   = initial{Generation: 4}
)

// up starts the agent and brings a TLS session up at t=1 s.
func up() []Event { return []Event{ev(0, EvStart), ev(sec, EvDialOK)} }

// upWS starts the agent, fails TLS twice and brings a WebSocket session up
// at t=4 s.
func upWS() []Event {
	return []Event{ev(0, EvStart), dialFailed(sec, "tls"), ev(2*sec, EvTick), dialFailed(2*sec, "tls"), ev(4*sec, EvTick), ev(4*sec, EvDialOK)}
}

func with(base []Event, more ...Event) []Event { return append(append([]Event{}, base...), more...) }

func genLadder() lfile {
	var cs []lcase
	add := func(c lcase) { cs = append(cs, c) }

	add(run("start-dials-tls", fresh, up()...))
	add(run("start-with-persisted-flags-off-holds", off, ev(0, EvStart), ev(5*minute, EvTick), flags(6*minute, 5, "ON"), ev(6*minute+30*sec, EvTick), ev(7*minute, EvDialOK)))
	add(run("no-flags-ever-dials", fresh, ev(0, EvStart), ev(hr, EvTick)))
	add(run("tls-blocked-falls-to-websocket", fresh, upWS()...))
	add(run("websocket-reprobes-tls-and-switches", fresh, with(upWS(),
		Event{At: 900 * sec, Kind: EvReceived}, ev(904*sec, EvTick), dialFailed(905*sec, "tls"),
		Event{At: 2700 * sec, Kind: EvReceived}, ev(2705*sec, EvTick), ev(2706*sec, EvDialOK))...))
	add(run("websocket-reprobe-backoff-doubles-to-cap", fresh, with(upWS(),
		ev(904*sec, EvTick), dialFailed(904*sec, "tls"), ev(2704*sec, EvTick), dialFailed(2704*sec, "tls"),
		ev(6304*sec, EvTick), dialFailed(6304*sec, "tls"), ev(13504*sec, EvTick), dialFailed(13504*sec, "tls"),
		ev(27904*sec, EvTick), dialFailed(27904*sec, "tls"))...))
	add(run("websocket-session-lost-stays-websocket", fresh, with(upWS(), ev(10*sec, EvSessionLost), ev(11*sec, EvDialOK))...))
	add(run("alpn-refused-on-both-carriages-update-required", fresh,
		ev(0, EvStart), dialFailed(sec, "alpn"), ev(2*sec, EvTick), dialFailed(2*sec, "alpn"), ev(4*sec, EvTick), dialFailed(4*sec, "subprotocol"),
		ev(4*sec+15*minute, EvTick), ev(4*sec+15*minute, EvDialOK)))
	add(run("network-change-resets-carriage", fresh,
		ev(0, EvStart), dialFailed(sec, "tls"), ev(2*sec, EvTick), dialFailed(2*sec, "tls"), ev(2500, EvNetwork)))
	add(run("reconnect-backoff-caps-at-30s", fresh, with(up(),
		ev(10*sec, EvSessionLost), dialFailed(11*sec, "dial"), ev(12*sec, EvTick), dialFailed(12*sec, "dial"),
		ev(14*sec, EvTick), dialFailed(14*sec, "dial"), ev(18*sec, EvTick), dialFailed(18*sec, "dial"),
		ev(26*sec, EvTick), dialFailed(26*sec, "dial"), ev(42*sec, EvTick), dialFailed(42*sec, "dial"),
		ev(72*sec, EvTick), dialFailed(72*sec, "dial"), ev(hr, EvTick), ev(hr, EvDialOK))...))
	add(run("transient-refusals-keep-carriage", fresh,
		ev(0, EvStart), refused(sec, "EDGE_NOT_READY"), ev(2*sec, EvTick), refused(2*sec, "OVERLOADED"), ev(4*sec, EvTick), refused(4*sec, "BAD_REQUEST")))
	add(run("flapping-sessions", fresh, with(up(),
		ev(10*sec, EvSessionLost), ev(11*sec, EvDialOK),
		ev(20*sec, EvSessionLost), dialFailed(21*sec, "dial"), ev(22*sec, EvTick), ev(22*sec, EvDialOK),
		ev(30*sec, EvSessionLost), ev(31*sec, EvDialOK))...))
	for _, c := range []string{"VERSION_TOO_OLD", "PROTOCOL_DISABLED", "TOO_MANY_ROUTES"} {
		add(run("refused-"+c+"-holds-and-redials", fresh, ev(0, EvStart), refused(sec, c),
			ev(sec+5*minute, EvTick), ev(sec+15*minute, EvTick), refused(2*sec+15*minute, c),
			ev(2*sec+45*minute, EvTick), ev(3*sec+45*minute, EvDialOK)))
	}
	add(run("edge-too-old-update-required", fresh, with(up(), ev(10*sec, EvSessionLost), dialFailed(11*sec, "edge_too_old"))...))
	add(run("maintenance-hold-left-by-newer-flags-on", fresh,
		ev(0, EvStart), refused(sec, "PROTOCOL_DISABLED"), flags(2*sec, 1, "ON"), flags(3*sec, 2, "ON"), ev(33*sec, EvTick), ev(34*sec, EvDialOK)))
	add(run("maintenance-hold-confirmed-by-flags-off", fresh,
		ev(0, EvStart), refused(sec, "PROTOCOL_DISABLED"), flags(2*sec, 2, "OFF"), ev(hr, EvTick)))
	add(run("auth-refusal-unconfirmed-redials-slowly", fresh,
		ev(0, EvStart), refused(sec, "KEY_REVOKED"), state(2*sec, "active", "active"), ev(sec+15*minute, EvTick), ev(sec+15*minute, EvDialOK)))
	add(run("auth-refusal-confirmed-hold", fresh,
		ev(0, EvStart), refused(sec, "KEY_REVOKED"), state(2*sec, "revoked", "active"),
		ev(2*sec+5*minute, EvTick), state(3*sec+5*minute, "active", "active"), ev(33*sec+5*minute, EvTick)))
	add(run("invalid-proof-never-holds-alone", fresh,
		ev(0, EvStart), refused(sec, "INVALID_PROOF"), ev(sec+15*minute, EvTick), refused(2*sec+15*minute, "ACCOUNT_SUSPENDED"), refused(3*sec+15*minute, "NOT_ENROLLED")))
	add(run("liveness-traffic-without-pong", fresh, with(up(),
		Event{At: 10 * sec, Kind: EvReceived}, ev(30*sec, EvTick), Event{At: 31 * sec, Kind: EvReceived},
		ev(50*sec, EvTick), Event{At: 51 * sec, Kind: EvReceived}, ev(71*sec, EvTick),
		ev(85*sec, EvTick), ev(86*sec, EvTick))...))
	add(run("liveness-ping-answered-by-any-byte", fresh, with(up(),
		ev(21*sec, EvTick), Event{At: 30 * sec, Kind: EvReceived}, ev(36*sec, EvTick))...))
	add(run("drain-reconnect-same-run-make-before-break", fresh, with(up(),
		drain(10*sec, "ROLLOUT", "RECONNECT", false), ev(11*sec, EvDialOK), Event{At: 12 * sec, Kind: EvReceived})...))
	add(run("drain-max-age", fresh, with(up(), drain(10*sec, "MAX_AGE", "RECONNECT", false), ev(11*sec, EvDialOK))...))
	add(run("drain-second-dial-fails-then-old-closes", fresh, with(up(),
		drain(10*sec, "REBALANCE", "ACTION_UNSPECIFIED", false), dialFailed(11*sec, "dial"), ev(20*sec, EvSessionLost))...))
	add(run("drain-second-dial-in-flight-when-old-closes", fresh, with(up(),
		drain(10*sec, "ROLLOUT", "RECONNECT", false), ev(20*sec, EvSessionLost), ev(21*sec, EvDialOK))...))
	add(run("drain-superseded-hold-pauses-60s", fresh, with(up(),
		drain(10*sec, "SUPERSEDED", "HOLD", false), ev(60*sec, EvTick), ev(70*sec, EvTick), ev(71*sec, EvDialOK))...))
	add(run("drain-kill-switch-hold-while-flags-on", fresh, with(up(), drain(10*sec, "KILL_SWITCH", "HOLD", false), refused(11*sec, "PROTOCOL_DISABLED"))...))
	add(run("kill-switch-signed-flags-off", fresh, with(up(), flags(10*sec, 2, "OFF"), ev(hr, EvTick), flags(hr+sec, 3, "ON"), ev(hr+31*sec, EvTick), ev(hr+32*sec, EvDialOK))...))
	add(run("flags-rollback-refused", fresh, with(up(), flags(10*sec, 2, "ON"), flags(11*sec, 2, "OFF"), flags(12*sec, 1, "OFF"))...))
	add(run("key-rotated-with-pending-key", fresh, with(up(),
		drain(10*sec, "KEY_ROTATED", "RECONNECT", true), ev(11*sec, EvDialOK))...))
	add(run("key-rotated-without-pending-key", fresh, with(up(),
		drain(10*sec, "KEY_ROTATED", "RECONNECT", false), ev(11*sec, EvDialOK))...))
	add(run("legacy-reactivated-revoke-device-confirmed", fresh, with(up(),
		revoke(10*sec, "DEVICE"), refused(11*sec, "KEY_REVOKED"), state(12*sec, "revoked", "active"))...))
	add(run("revoke-device-unconfirmed", fresh, with(up(),
		revoke(10*sec, "DEVICE"), state(11*sec, "active", "active"), ev(12*sec, EvDialOK))...))
	add(run("revoke-account-confirmed", fresh, with(up(),
		revoke(10*sec, "ACCOUNT"), state(11*sec, "active", "suspended"), flags(12*sec, 1, "ON"), state(13*sec, "active", "active"))...))
	add(run("revoke-app-keeps-session", fresh, with(up(), revoke(10*sec, "APP"))...))
	add(run("repair-needed-hold", fresh, ev(0, EvStart), Event{At: sec, Kind: EvRepair}, ev(5*minute+sec, EvTick), state(6*minute, "active", "active")))
	add(run("unsigned-statements-never-hold-without-redial", fresh, with(up(),
		revoke(10*sec, "DEVICE"), refused(11*sec, "KEY_REVOKED"), refused(12*sec, "ACCOUNT_SUSPENDED"),
		ev(12*sec+15*minute, EvTick), refused(13*sec+15*minute, "PROTOCOL_DISABLED"))...))
	return lfile{Format: "ladder", Note: vkeys.Note, Cases: cs}
}
