package ladder

import (
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

type initial struct {
	State      string `json:"state"`
	Generation int64  `json:"generation"`
	ModeOn     bool   `json:"mode_on"`
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
	m := New(in.State, in.Generation, in.ModeOn)
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

func state(at int64, dev, acct string, v1 bool) Event {
	return Event{At: at, Kind: EvSignedState, DeviceStatus: dev, AccountStatus: acct, V1Live: v1}
}

var enrolled = initial{State: FRPC}

// up brings an enrolled agent from FRPC to OWN at t=0..40 s.
func up() []Event {
	return []Event{flags(0, 1, "ON"), ev(30*sec, EvTick), ev(31*sec, EvDialOK), ev(41*sec, EvTick)}
}

func with(base []Event, more ...Event) []Event { return append(append([]Event{}, base...), more...) }

func genLadder() lfile {
	var cs []lcase
	add := func(c lcase) { cs = append(cs, c) }

	add(run("probe-success-make-before-break", enrolled, up()...))
	add(run("no-flags-ever-stays-frpc", enrolled, ev(hr, EvTick), dialFailed(hr, "dial")))
	add(run("flags-off-stays-frpc", enrolled, flags(0, 1, "OFF"), ev(hr, EvTick)))
	add(run("probe-transient-failures-double-to-cap", enrolled,
		flags(0, 1, "ON"), ev(30*sec, EvTick), dialFailed(31*sec, "dial"),
		ev(31*sec+15*minute, EvTick), refused(32*sec+15*minute, "EDGE_NOT_READY"),
		ev(32*sec+45*minute, EvTick), refused(33*sec+45*minute, "OVERLOADED"),
		ev(34*sec+105*minute, EvTick), dialFailed(35*sec+105*minute, "tls"),
		ev(36*sec+225*minute, EvTick), dialFailed(37*sec+225*minute, "ack_signature"),
		ev(38*sec+465*minute, EvTick), dialFailed(39*sec+465*minute, "dial"),
		flags(40*sec+465*minute, 2, "ON")))
	add(run("probe-terminal-refusal-blocks-until-new-generation", enrolled,
		flags(0, 1, "ON"), ev(30*sec, EvTick), refused(31*sec, "PROTOCOL_DISABLED"),
		ev(5*hr, EvTick), flags(5*hr, 2, "ON")))
	for _, c := range []string{"VERSION_TOO_OLD", "TOO_MANY_ROUTES"} {
		add(run("probe-terminal-"+c, enrolled, flags(0, 1, "ON"), ev(30*sec, EvTick), refused(31*sec, c), ev(5*hr, EvTick)))
	}
	for _, c := range []string{"alpn", "edge_too_old"} {
		add(run("probe-terminal-"+c, enrolled, flags(0, 1, "ON"), ev(30*sec, EvTick), dialFailed(31*sec, c), ev(5*hr, EvTick)))
	}
	add(run("probe-auth-refusal-unconfirmed-stays-frpc", enrolled,
		flags(0, 1, "ON"), ev(30*sec, EvTick), refused(31*sec, "KEY_REVOKED"), state(32*sec, "active", "active", false)))
	add(run("probe-auth-refusal-confirmed-hold", enrolled,
		flags(0, 1, "ON"), ev(30*sec, EvTick), refused(31*sec, "KEY_REVOKED"), state(32*sec, "revoked", "active", false),
		ev(32*sec+5*minute, EvTick), state(33*sec+5*minute, "active", "active", false), ev(64*sec+5*minute, EvTick)))
	add(run("probe-invalid-proof-never-hold-alone", enrolled,
		flags(0, 1, "ON"), ev(30*sec, EvTick), refused(31*sec, "INVALID_PROOF"), refused(32*sec, "ACCOUNT_SUSPENDED")))
	add(run("flapping-within-fallback-timer", enrolled, with(up(),
		ev(50*sec, EvSessionLost), ev(51*sec, EvDialOK),
		ev(60*sec, EvSessionLost), dialFailed(61*sec, "dial"), ev(62*sec, EvTick), ev(62*sec, EvDialOK),
		ev(70*sec, EvSessionLost), ev(71*sec, EvDialOK))...))
	add(run("reconnect-three-failures-fall-back", enrolled, with(up(),
		ev(50*sec, EvSessionLost), dialFailed(51*sec, "dial"), ev(52*sec, EvTick), dialFailed(53*sec, "tls"),
		ev(55*sec, EvTick), refused(56*sec, "OVERLOADED"))...))
	add(run("reconnect-60s-fall-back", enrolled, with(up(),
		ev(50*sec, EvSessionLost), ev(109*sec, EvTick), ev(110*sec, EvTick))...))
	add(run("reconnect-network-change-redials-now", enrolled, with(up(),
		ev(50*sec, EvSessionLost), dialFailed(51*sec, "dial"), ev(51500, EvNetwork))...))
	add(run("reconnect-terminal-refusal", enrolled, with(up(),
		ev(50*sec, EvSessionLost), refused(51*sec, "PROTOCOL_DISABLED"))...))
	flap := with(up(), ev(50*sec, EvSessionLost), ev(110*sec, EvTick),
		ev(110*sec+15*minute, EvTick), ev(111*sec+15*minute, EvDialOK),
		ev(200*sec+15*minute, EvSessionLost), ev(260*sec+15*minute, EvTick),
		ev(260*sec+45*minute, EvTick))
	add(run("flapping-across-reprobe-backoff", enrolled, flap...))
	add(run("liveness-traffic-without-pong", enrolled, with(up(),
		Event{At: 50 * sec, Kind: EvReceived}, ev(65*sec, EvTick), Event{At: 66 * sec, Kind: EvReceived},
		ev(80*sec, EvTick), Event{At: 81 * sec, Kind: EvReceived}, ev(100*sec, EvTick),
		ev(101*sec, EvTick), ev(115*sec, EvTick), ev(116*sec, EvTick))...))
	add(run("liveness-ping-answered-by-any-byte", enrolled, with(up(),
		ev(61*sec, EvTick), Event{At: 70 * sec, Kind: EvReceived}, ev(76*sec, EvTick))...))
	add(run("drain-reconnect-same-run-make-before-break", enrolled, with(up(),
		drain(50*sec, "ROLLOUT", "RECONNECT", false), ev(51*sec, EvDialOK), Event{At: 52 * sec, Kind: EvReceived})...))
	add(run("drain-max-age", enrolled, with(up(), drain(50*sec, "MAX_AGE", "RECONNECT", false), ev(51*sec, EvDialOK))...))
	add(run("drain-second-dial-fails-then-old-closes", enrolled, with(up(),
		drain(50*sec, "REBALANCE", "ACTION_UNSPECIFIED", false), dialFailed(51*sec, "dial"), ev(60*sec, EvSessionLost))...))
	add(run("drain-superseded-stop", enrolled, with(up(),
		drain(50*sec, "SUPERSEDED", "STOP", false), ev(100*sec, EvTick), ev(110*sec, EvTick))...))
	add(run("drain-use-frpc-while-flags-on", enrolled, with(up(), drain(50*sec, "KILL_SWITCH", "USE_FRPC", false))...))
	add(run("kill-switch-signed-flags-off", enrolled, with(up(), flags(50*sec, 2, "OFF"), ev(hr, EvTick))...))
	add(run("flags-rollback-refused", enrolled, with(up(), flags(50*sec, 1, "OFF"), flags(51*sec, 0, "OFF"))...))
	add(run("key-rotated-with-pending-key", enrolled, with(up(),
		drain(50*sec, "KEY_ROTATED", "RECONNECT", true), ev(51*sec, EvDialOK))...))
	add(run("key-rotated-without-pending-key", enrolled, with(up(),
		drain(50*sec, "KEY_ROTATED", "RECONNECT", false), ev(51*sec, EvDialOK))...))
	add(run("legacy-reactivated-revoke-device-confirmed", enrolled, with(up(),
		revoke(50*sec, "DEVICE"), refused(51*sec, "KEY_REVOKED"), state(52*sec, "revoked", "active", false))...))
	add(run("revoke-device-unconfirmed", enrolled, with(up(),
		revoke(50*sec, "DEVICE"), state(51*sec, "active", "active", false), ev(52*sec, EvDialOK))...))
	add(run("revoke-account-confirmed", enrolled, with(up(),
		revoke(50*sec, "ACCOUNT"), state(51*sec, "active", "suspended", false))...))
	add(run("revoke-app-keeps-session", enrolled, with(up(), revoke(50*sec, "APP"))...))
	add(run("repair-needed-hold", enrolled, Event{At: 0, Kind: EvRepair}, ev(5*minute, EvTick)))
	add(run("v1-without-signed-live-token", enrolled,
		Event{At: 0, Kind: EvFRPCRefused, Authenticated: true}, Event{At: sec, Kind: EvFRPCRefused},
		dialFailed(2*sec, "dial"), state(3*sec, "active", "active", false)))
	add(run("v1-with-signed-live-token", enrolled,
		Event{At: 0, Kind: EvFRPCRefused, Authenticated: true}, state(sec, "pending", "active", true), Event{At: 2 * sec, Kind: EvEnrolled}))
	add(run("v1-unauthenticated-refusal-ignored", enrolled,
		state(0, "pending", "active", true), Event{At: sec, Kind: EvFRPCRefused}))
	add(run("unenrolled-v1-enrols", initial{State: V1}, state(0, "pending", "active", true), Event{At: sec, Kind: EvEnrolled}))
	add(run("unsigned-statements-never-hold", enrolled, with(up(),
		revoke(50*sec, "DEVICE"), refused(51*sec, "KEY_REVOKED"), refused(52*sec, "ACCOUNT_SUSPENDED"),
		drain(53*sec, "KILL_SWITCH", "USE_FRPC", false), ev(120*sec, EvTick))...))
	return lfile{Format: "ladder", Note: vkeys.Note, Cases: cs}
}
