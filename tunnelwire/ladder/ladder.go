// Package ladder is the reference model of the agent's transport ladder:
// the own protocol over raw TLS, then over a WebSocket on 443, then
// reconnecting with backoff, then HOLD. There is no other transport. It is
// a pure state machine over events with a caller-supplied clock, shared by
// the agent and the test harness through ladder.json.
//
// Unsigned edge statements (refusals, Drain, Revoke, session loss) never
// delete anything, and a HOLD they cause always keeps a re-dial timer. A
// HOLD without one needs control-key signed flags or a nonce-bound signed
// heartbeat, which the caller verifies before passing it in, or the local
// repair-needed fact.
package ladder

import (
	"slices"
	"time"
)

// States.
const (
	Own          = "OWN"          // own protocol over raw TLS: session up, or the first dial
	OwnWS        = "OWN_WS"       // own protocol over a WebSocket on 443
	Reconnecting = "RECONNECTING" // no session; redials with backoff
	Hold         = "HOLD"         // no tunnel; nothing deleted
)

// Transports, as in HelloBody.transport.
const (
	TLS       = "TLS"
	WebSocket = "WEBSOCKET"
)

// Hold reasons.
const (
	HoldFlagsOff      = "flags_off"       // signed flags evaluate to OFF
	HoldRevoked       = "revoked"         // signed heartbeat: key revoked or compromised
	HoldSuspended     = "suspended"       // signed heartbeat: account suspended or banned
	HoldRepair        = "repair_needed"   // rotation recovery failed
	HoldUpdate        = "update_required" // VERSION_TOO_OLD, edge_too_old, or two subprotocol refusals
	HoldMaintenance   = "maintenance"     // PROTOCOL_DISABLED
	HoldTooManyRoutes = "too_many_routes" // TOO_MANY_ROUTES
)

// Event kinds.
const (
	EvStart       = "start"         // process start
	EvFlags       = "flags"         // signed flags, either carrier: Generation, Mode
	EvTick        = "tick"          // clock advanced to At
	EvDialOK      = "dial_ok"       // HelloAck verified and first RouteSet applied
	EvDialFailed  = "dial_failed"   // Cause: dial, tls, alpn, subprotocol, ack_signature, edge_too_old
	EvRefused     = "refused"       // Code: a RefuseCode name
	EvSessionLost = "session_lost"  // the active session ended
	EvReceived    = "rx"            // any byte received on the session
	EvDrain       = "drain"         // Reason, Action, PendingKey
	EvRevoke      = "revoke"        // Scope
	EvSignedState = "signed_state"  // verified heartbeat: DeviceStatus, AccountStatus
	EvRepair      = "repair_needed" // rotation recovery failed
	EvNetwork     = "network_change"
	// EvTimer fires the timer named by Reason at a caller-chosen point
	// inside its window (full jitter); EvTick fires it at the window's end.
	EvTimer = "timer"
)

// Actions the caller performs. Dials use Output.Transport.
const (
	ActDial           = "dial"
	ActDialSecond     = "dial_second_session"
	ActSwitchSession  = "switch_session"
	ActCloseSession   = "close_session"
	ActSendPing       = "send_ping"
	ActHeartbeat      = "request_signed_heartbeat"
	ActCommitRotation = "commit_rotation"
	ActEndAppSessions = "end_app_sessions"
	ActStopTunnels    = "stop_tunnels"
	ActCountSupersede = "count_supersede"
	ActFlagsRollback  = "flags_rollback_refused"
)

// Timers and defaults.
const (
	TimerDial      = "dial"
	TimerRedial    = "redial"
	TimerProbe     = "probe_tls"
	TimerHeartbeat = "heartbeat"

	DialJitter        = 30 * time.Second
	ReprobeBase       = 15 * time.Minute
	ReprobeCap        = 4 * time.Hour
	RedialBase        = time.Second
	RedialCap         = 30 * time.Second
	CarriageFailures  = 2
	NoMajorRefusals   = 2
	SupersedePause    = 60 * time.Second
	HoldPoll          = 5 * time.Minute
	DefaultPingEvery  = 20 * time.Second
	DefaultPingWithin = 15 * time.Second
)

// Event is one input. At is milliseconds on the caller's clock and must not
// go backwards.
type Event struct {
	At            int64  `json:"at"`
	Kind          string `json:"kind"`
	Generation    int64  `json:"generation,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Cause         string `json:"cause,omitempty"`
	Code          string `json:"code,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Action        string `json:"action,omitempty"`
	PendingKey    bool   `json:"pending_key,omitempty"`
	Scope         string `json:"scope,omitempty"`
	DeviceStatus  string `json:"device_status,omitempty"`
	AccountStatus string `json:"account_status,omitempty"`
}

// Window is a timer's firing window in absolute milliseconds.
type Window [2]int64

// Output is the model's state after an event. Transport is the carriage of
// the session, or of the next dial when there is none.
type Output struct {
	State     string            `json:"state"`
	Hold      string            `json:"hold,omitempty"`
	Transport string            `json:"transport"`
	Actions   []string          `json:"actions"`
	Timers    map[string]Window `json:"timers"`
}

// Machine is the ladder for one agent.
type Machine struct {
	state      string
	hold       string
	transport  string
	generation int64
	modeOn     bool
	up         bool
	second     bool
	secondTLS  bool
	attempts   int
	failures   int
	noMajor    int
	slowLevel  int
	probeLevel int
	timers     map[string]Window
	lastRx     int64
	pinged     bool
	pingAt     int64
	pingEvery  int64
	pingWithin int64
	now        int64
	actions    []string
}

// New returns a machine in OWN with the last persisted flags generation
// and mode (ON when none was ever received).
func New(generation int64, modeOn bool) *Machine {
	return &Machine{
		state: Own, transport: TLS, generation: generation, modeOn: modeOn,
		timers:    map[string]Window{},
		pingEvery: DefaultPingEvery.Milliseconds(), pingWithin: DefaultPingWithin.Milliseconds(),
	}
}

// SetPing applies the clamped ping values of a HelloAck.
func (m *Machine) SetPing(every, within time.Duration) {
	m.pingEvery, m.pingWithin = every.Milliseconds(), within.Milliseconds()
}

// State returns the current state.
func (m *Machine) State() string { return m.state }

func (m *Machine) act(a ...string) { m.actions = append(m.actions, a...) }

func (m *Machine) set(name string, lo, hi int64) { m.timers[name] = Window{lo, hi} }

func (m *Machine) clearAll() { m.timers = map[string]Window{} }

func backoff(base, cap time.Duration, level int) int64 {
	d := base
	for i := 0; i < level && d < cap; i++ {
		d *= 2
	}
	return min(d, cap).Milliseconds()
}

func other(t string) string {
	if t == TLS {
		return WebSocket
	}
	return TLS
}

func signedHold(reason string) bool {
	return reason == HoldFlagsOff || reason == HoldRevoked || reason == HoldSuspended || reason == HoldRepair
}

// toHold stops every tunnel. A hold on an unsigned statement asks for a
// signed heartbeat at once and keeps a slow re-dial timer.
func (m *Machine) toHold(reason string) {
	m.state, m.hold, m.up, m.second = Hold, reason, false, false
	m.clearAll()
	m.act(ActStopTunnels)
	m.set(TimerHeartbeat, m.now+HoldPoll.Milliseconds(), m.now+HoldPoll.Milliseconds())
	if !signedHold(reason) {
		m.act(ActHeartbeat)
		m.slowRedial()
	}
}

func (m *Machine) slowRedial() {
	m.set(TimerRedial, m.now, m.now+backoff(ReprobeBase, ReprobeCap, m.slowLevel))
	m.slowLevel++
}

// reconnecting leaves any session and resets the carriage state.
func (m *Machine) reconnecting() {
	m.state, m.hold, m.up = Reconnecting, "", false
	m.clearAll()
	m.attempts, m.failures = 0, 0
}

// redialSoon leaves HOLD with a jittered dial over TLS.
func (m *Machine) redialSoon() {
	m.reconnecting()
	m.transport, m.second = TLS, false
	m.noMajor = 0
	m.set(TimerDial, m.now, m.now+DialJitter.Milliseconds())
}

// lost ends the session; an in-flight second dial becomes the redial.
func (m *Machine) lost() {
	m.reconnecting()
	if m.second {
		m.second = false
		if m.secondTLS {
			m.transport = TLS
		}
		return
	}
	m.act(ActDial)
}

func (m *Machine) sessionUp() {
	m.up, m.hold, m.lastRx, m.pinged = true, "", m.now, false
	m.attempts, m.failures, m.slowLevel = 0, 0, 0
	m.noMajor = 0
	delete(m.timers, TimerDial)
	delete(m.timers, TimerRedial)
	m.state = Own
	if m.transport == WebSocket {
		m.state = OwnWS
		if _, ok := m.timers[TimerProbe]; !ok {
			m.set(TimerProbe, m.now, m.now+backoff(ReprobeBase, ReprobeCap, m.probeLevel))
		}
		return
	}
	m.probeLevel = 0
	delete(m.timers, TimerProbe)
}

type failure int

const (
	transient failure = iota
	carriage
	auth
	update
	maintenance
	tooManyRoutes
)

func classify(e Event) failure {
	switch e.Cause + e.Code {
	case "VERSION_TOO_OLD", "edge_too_old":
		return update
	case "PROTOCOL_DISABLED":
		return maintenance
	case "TOO_MANY_ROUTES":
		return tooManyRoutes
	case "KEY_REVOKED", "ACCOUNT_SUSPENDED", "INVALID_PROOF", "NOT_ENROLLED":
		return auth
	}
	if e.Kind == EvDialFailed {
		return carriage
	}
	return transient
}

// Step applies one event and returns the resulting output.
func (m *Machine) Step(e Event) Output {
	m.actions = nil
	m.now = e.At
	switch e.Kind {
	case EvStart:
		if m.modeOn {
			m.act(ActDial)
		} else {
			m.toHold(HoldFlagsOff)
		}
	case EvFlags:
		m.flags(e)
	case EvTick:
		m.tick()
	case EvTimer:
		if w, ok := m.timers[e.Reason]; ok && m.now >= w[0] {
			m.fire(e.Reason)
		}
	case EvDialOK:
		m.dialOK()
	case EvDialFailed, EvRefused:
		m.failed(e)
	case EvSessionLost:
		if m.up {
			m.lost()
		}
	case EvReceived:
		m.lastRx, m.pinged = m.now, false
	case EvDrain:
		m.drain(e)
	case EvRevoke:
		m.revoke(e)
	case EvSignedState:
		m.signedState(e)
	case EvRepair:
		m.toHold(HoldRepair)
	case EvNetwork:
		if m.state == Reconnecting {
			m.reconnecting()
			m.transport = TLS
			m.noMajor = 0
			m.act(ActDial)
		}
	}
	return m.output()
}

func (m *Machine) output() Output {
	t := make(map[string]Window, len(m.timers))
	for k, v := range m.timers {
		t[k] = v
	}
	a := slices.Clone(m.actions)
	if a == nil {
		a = []string{}
	}
	return Output{State: m.state, Hold: m.hold, Transport: m.transport, Actions: a, Timers: t}
}

func (m *Machine) flags(e Event) {
	if e.Generation <= m.generation {
		m.act(ActFlagsRollback)
		return
	}
	m.generation, m.modeOn = e.Generation, e.Mode == "ON"
	switch {
	case m.state == Hold && m.hold != HoldFlagsOff && signedHold(m.hold):
	case !m.modeOn:
		if m.hold != HoldFlagsOff {
			m.toHold(HoldFlagsOff)
		}
	case m.state == Hold:
		m.slowLevel = 0
		m.redialSoon()
	}
}

func (m *Machine) tick() {
	for _, name := range []string{TimerDial, TimerRedial, TimerProbe, TimerHeartbeat} {
		w, ok := m.timers[name]
		if !ok || m.now < w[1] {
			continue
		}
		m.fire(name)
	}
	if !m.up {
		return
	}
	switch {
	case !m.pinged && m.now-m.lastRx >= m.pingEvery:
		m.pinged, m.pingAt = true, m.now
		m.act(ActSendPing)
	case m.pinged && m.now-m.pingAt >= m.pingWithin:
		m.lost()
	}
}

func (m *Machine) fire(name string) {
	delete(m.timers, name)
	switch name {
	case TimerDial:
		m.act(ActDial)
	case TimerRedial:
		if m.state == Hold {
			m.reconnecting()
			m.transport, m.noMajor = TLS, 0
		}
		m.act(ActDial)
	case TimerProbe:
		if !m.second {
			m.second, m.secondTLS = true, true
			m.act(ActDialSecond)
		}
	case TimerHeartbeat:
		m.act(ActHeartbeat)
		m.set(TimerHeartbeat, m.now+HoldPoll.Milliseconds(), m.now+HoldPoll.Milliseconds())
	}
}

func (m *Machine) dialOK() {
	switch {
	case m.up && m.second:
		m.second = false
		m.act(ActSwitchSession)
		if m.secondTLS {
			m.transport = TLS
		}
		m.sessionUp()
	case !m.up && m.state != Hold:
		m.sessionUp()
	default:
		m.act(ActCloseSession)
	}
}

func (m *Machine) failed(e Event) {
	if m.up {
		if m.second {
			m.second = false
			if m.secondTLS && m.transport == WebSocket {
				m.probeLevel++
				m.set(TimerProbe, m.now, m.now+backoff(ReprobeBase, ReprobeCap, m.probeLevel))
			}
		}
		return
	}
	if m.state == Hold {
		return
	}
	m.state = Reconnecting
	switch classify(e) {
	case update:
		m.toHold(HoldUpdate)
	case maintenance:
		m.toHold(HoldMaintenance)
	case tooManyRoutes:
		m.toHold(HoldTooManyRoutes)
	case auth:
		m.act(ActHeartbeat)
		m.slowRedial()
	case carriage:
		if e.Cause == "subprotocol" {
			m.noMajor++
			if m.noMajor >= NoMajorRefusals {
				m.toHold(HoldUpdate)
				return
			}
		}
		m.failures++
		if m.failures >= CarriageFailures {
			m.transport, m.failures = other(m.transport), 0
		}
		m.redial()
	default:
		m.redial()
	}
}

func (m *Machine) redial() {
	m.attempts++
	m.set(TimerRedial, m.now, m.now+backoff(RedialBase, RedialCap, m.attempts-1))
}

func (m *Machine) drain(e Event) {
	if !m.up {
		return
	}
	switch {
	case e.Reason == "SUPERSEDED" && e.Action == "HOLD":
		m.act(ActCloseSession, ActCountSupersede)
		m.second = false
		m.reconnecting()
		m.set(TimerRedial, m.now+SupersedePause.Milliseconds(), m.now+SupersedePause.Milliseconds())
	case e.Reason == "KEY_ROTATED" && !e.PendingKey:
		m.act(ActCloseSession)
		m.second = false
		m.lost()
	default:
		if e.Action == "HOLD" {
			m.act(ActHeartbeat)
		}
		if e.Reason == "KEY_ROTATED" {
			m.act(ActCommitRotation)
		}
		if !m.second {
			m.second, m.secondTLS = true, false
			m.act(ActDialSecond)
		}
	}
}

func (m *Machine) revoke(e Event) {
	if !m.up {
		return
	}
	switch e.Scope {
	case "APP":
		m.act(ActEndAppSessions)
	case "DEVICE", "ACCOUNT":
		m.act(ActCloseSession, ActHeartbeat)
		m.second = false
		m.lost()
	}
}

func (m *Machine) signedState(e Event) {
	switch {
	case e.DeviceStatus == "revoked" || e.DeviceStatus == "compromised":
		m.toHold(HoldRevoked)
	case e.AccountStatus != "active":
		m.toHold(HoldSuspended)
	case e.DeviceStatus != "active" || m.state != Hold || !signedHold(m.hold) || m.hold == HoldFlagsOff:
	case m.modeOn:
		m.slowLevel = 0
		m.redialSoon()
	default:
		m.toHold(HoldFlagsOff)
	}
}
