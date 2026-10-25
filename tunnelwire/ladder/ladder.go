// Package ladder is the reference model of the agent's transport ladder:
// own protocol, frpc, v1, and HOLD. It is a pure state machine over events
// with a caller-supplied clock, shared by the agent and the test harness
// through ladder.json.
//
// Unsigned edge statements (refusals, Drain, Revoke, session loss) never
// move the agent below frpc and never into HOLD. HOLD and V1 need a
// control-key signed, nonce-bound heartbeat statement, which the caller
// verifies before passing it in as a SignedState event.
package ladder

import (
	"slices"
	"time"
)

// States.
const (
	FRPC            = "FRPC"
	Probing         = "PROBING"
	Own             = "OWN"
	OwnReconnecting = "OWN_RECONNECTING"
	Hold            = "HOLD"
	V1              = "V1"
)

// Event kinds.
const (
	EvFlags       = "flags"         // signed flags, either carrier: Generation, Mode
	EvTick        = "tick"          // clock advanced to At
	EvDialOK      = "dial_ok"       // HelloAck verified and first RouteSet applied
	EvDialFailed  = "dial_failed"   // Cause: dial, tls, alpn, ack_signature, edge_too_old
	EvRefused     = "refused"       // Code: a RefuseCode name
	EvSessionLost = "session_lost"  // the active session ended
	EvReceived    = "rx"            // any byte received on the session
	EvDrain       = "drain"         // Reason, Action, PendingKey
	EvRevoke      = "revoke"        // Scope
	EvSignedState = "signed_state"  // verified heartbeat: DeviceStatus, AccountStatus, V1Live
	EvRepair      = "repair_needed" // rotation recovery failed
	EvFRPCRefused = "frpc_refused"  // Authenticated: from an frps whose certificate verified
	EvNetwork     = "network_change"
	EvEnrolled    = "enrolled" // an active key was accepted
)

// Actions the caller performs.
const (
	ActDial            = "dial"
	ActDialSecond      = "dial_second_session"
	ActSwitchSession   = "switch_session"
	ActCloseSession    = "close_session"
	ActStartFRPC       = "start_frpc"
	ActStopFRPC        = "stop_frpc"
	ActCloseAfterFRPC  = "close_session_after_frpc_up"
	ActSendPing        = "send_ping"
	ActHeartbeat       = "request_signed_heartbeat"
	ActCommitRotation  = "commit_rotation"
	ActEndAppSessions  = "end_app_sessions"
	ActStopTunnels     = "stop_tunnels"
	ActUseV1           = "use_v1_token"
	ActDeleteV1Copy    = "delete_v1_token_copy"
	ActCountSupersede  = "count_supersede"
	ActFlagsRollback   = "flags_rollback_refused"
	ActIgnoredUnsigned = "ignored_unauthenticated"
)

// Timers and defaults.
const (
	TimerDial      = "dial"
	TimerProbe     = "probe"
	TimerHandover  = "stop_frpc"
	TimerRedial    = "redial"
	TimerFallback  = "fallback"
	TimerHeartbeat = "heartbeat"

	ProbeJitter       = 30 * time.Second
	ReprobeBase       = 15 * time.Minute
	ReprobeCap        = 4 * time.Hour
	RedialBase        = time.Second
	RedialCap         = 30 * time.Second
	FallbackAfter     = 60 * time.Second
	FallbackAttempts  = 3
	HandoverDelay     = 10 * time.Second
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
	V1Live        bool   `json:"v1_token_live,omitempty"`
	Authenticated bool   `json:"authenticated,omitempty"`
}

// Window is a timer's firing window in absolute milliseconds.
type Window [2]int64

// Output is the model's state after an event.
type Output struct {
	State   string            `json:"state"`
	Actions []string          `json:"actions"`
	Timers  map[string]Window `json:"timers"`
}

// Machine is the ladder for one agent.
type Machine struct {
	state      string
	generation int64
	modeOn     bool
	blocked    bool
	probeLevel int
	attempts   int
	timers     map[string]Window
	second     bool
	lastRx     int64
	pinged     bool
	pingAt     int64
	pingEvery  int64
	pingWithin int64
	v1Live     bool
	frpcAuthNo bool
	v1Deleted  bool
	now        int64
	actions    []string
}

// New returns a machine in state (FRPC for an enrolled agent, V1 for one
// that never enrolled) with the last persisted flags generation and mode.
func New(state string, generation int64, modeOn bool) *Machine {
	return &Machine{
		state: state, generation: generation, modeOn: modeOn, timers: map[string]Window{},
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

func (m *Machine) clear(names ...string) {
	for _, n := range names {
		delete(m.timers, n)
	}
}

func (m *Machine) clearAll() { m.timers = map[string]Window{} }

func backoff(base, cap time.Duration, level int) int64 {
	d := base
	for i := 0; i < level && d < cap; i++ {
		d *= 2
	}
	return min(d, cap).Milliseconds()
}

// toFRPC moves to FRPC; startFRPC is set when frpc is not already running.
func (m *Machine) toFRPC(startFRPC bool) {
	m.state = FRPC
	m.second = false
	m.clearAll()
	if startFRPC {
		m.act(ActStartFRPC)
	}
}

// reprobe schedules the next probe after a failure, doubling up to the cap.
func (m *Machine) reprobe() {
	m.set(TimerProbe, m.now, m.now+backoff(ReprobeBase, ReprobeCap, m.probeLevel))
	m.probeLevel++
}

func (m *Machine) startProbe() {
	m.state = Probing
	m.clearAll()
	m.set(TimerDial, m.now, m.now+ProbeJitter.Milliseconds())
}

func (m *Machine) startReconnect() {
	m.state = OwnReconnecting
	m.attempts = 0
	m.clear(TimerHandover)
	m.set(TimerFallback, m.now+FallbackAfter.Milliseconds(), m.now+FallbackAfter.Milliseconds())
	if !m.second {
		m.act(ActDial)
	}
}

func (m *Machine) sessionUp() {
	m.lastRx, m.pinged, m.attempts = m.now, false, 0
	if !m.v1Deleted {
		m.v1Deleted = true
		m.act(ActDeleteV1Copy)
	}
}

type failure int

const (
	transient failure = iota
	terminal
	auth
)

func classify(e Event) failure {
	switch e.Cause + e.Code {
	case "alpn", "edge_too_old", "PROTOCOL_DISABLED", "VERSION_TOO_OLD", "TOO_MANY_ROUTES":
		return terminal
	case "KEY_REVOKED", "ACCOUNT_SUSPENDED", "INVALID_PROOF", "NOT_ENROLLED":
		return auth
	}
	return transient
}

func (m *Machine) failed(f failure) {
	switch m.state {
	case Probing:
		m.toFRPC(false)
		m.afterFailure(f)
	case OwnReconnecting:
		if f == transient {
			m.attempts++
			if m.attempts < FallbackAttempts {
				m.set(TimerRedial, m.now, m.now+backoff(RedialBase, RedialCap, m.attempts-1))
				return
			}
		}
		m.toFRPC(true)
		m.afterFailure(f)
	case Own:
		m.second = false
	}
}

func (m *Machine) afterFailure(f failure) {
	switch f {
	case terminal:
		m.blocked = true
	case auth:
		m.act(ActHeartbeat)
		m.reprobe()
	default:
		m.reprobe()
	}
}

// Step applies one event and returns the resulting output.
func (m *Machine) Step(e Event) Output {
	m.actions = nil
	m.now = e.At
	switch e.Kind {
	case EvFlags:
		m.flags(e)
	case EvTick:
		m.tick()
	case EvDialOK:
		m.dialOK()
	case EvDialFailed, EvRefused:
		m.failed(classify(e))
	case EvSessionLost:
		switch m.state {
		case Own:
			m.startReconnect()
		case Probing:
			m.failed(transient)
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
		m.hold()
	case EvFRPCRefused:
		m.frpcRefused(e)
	case EvNetwork:
		if m.state == OwnReconnecting {
			m.clear(TimerRedial)
			m.act(ActDial)
		}
	case EvEnrolled:
		if m.state == V1 {
			m.toFRPC(true)
		}
		m.v1Live, m.frpcAuthNo = false, false
		if !m.v1Deleted {
			m.v1Deleted = true
			m.act(ActDeleteV1Copy)
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
	return Output{State: m.state, Actions: a, Timers: t}
}

func (m *Machine) flags(e Event) {
	if e.Generation <= m.generation {
		m.act(ActFlagsRollback)
		return
	}
	m.generation, m.modeOn, m.blocked, m.probeLevel = e.Generation, e.Mode == "ON", false, 0
	switch m.state {
	case FRPC:
		if m.modeOn {
			m.startProbe()
		} else {
			m.clear(TimerProbe)
		}
	case Probing:
		if !m.modeOn {
			m.toFRPC(false)
		}
	case Own:
		if !m.modeOn {
			m.toFRPC(true)
			m.act(ActCloseAfterFRPC)
		}
	case OwnReconnecting:
		if !m.modeOn {
			m.toFRPC(true)
		}
	}
}

func (m *Machine) tick() {
	for _, name := range []string{TimerDial, TimerProbe, TimerHandover, TimerRedial, TimerFallback, TimerHeartbeat} {
		w, ok := m.timers[name]
		if !ok || m.now < w[1] {
			continue
		}
		delete(m.timers, name)
		switch name {
		case TimerDial, TimerRedial:
			m.act(ActDial)
		case TimerProbe:
			if m.modeOn && !m.blocked {
				m.state = Probing
				m.act(ActDial)
			}
		case TimerHandover:
			m.act(ActStopFRPC)
		case TimerFallback:
			m.toFRPC(true)
			m.reprobe()
			return
		case TimerHeartbeat:
			m.act(ActHeartbeat)
			m.set(TimerHeartbeat, m.now+HoldPoll.Milliseconds(), m.now+HoldPoll.Milliseconds())
		}
	}
	if m.state != Own {
		return
	}
	switch {
	case !m.pinged && m.now-m.lastRx >= m.pingEvery:
		m.pinged, m.pingAt = true, m.now
		m.act(ActSendPing)
	case m.pinged && m.now-m.pingAt >= m.pingWithin:
		m.startReconnect()
	}
}

func (m *Machine) dialOK() {
	switch m.state {
	case Probing:
		m.state = Own
		m.clearAll()
		m.set(TimerHandover, m.now+HandoverDelay.Milliseconds(), m.now+HandoverDelay.Milliseconds())
		m.sessionUp()
	case OwnReconnecting:
		m.state = Own
		m.second = false
		m.clear(TimerRedial, TimerFallback)
		m.sessionUp()
	case Own:
		if m.second {
			m.second = false
			m.act(ActSwitchSession)
			m.sessionUp()
		} else {
			m.act(ActCloseSession)
		}
	default:
		m.act(ActCloseSession)
	}
}

func (m *Machine) drain(e Event) {
	if m.state != Own {
		return
	}
	switch {
	case e.Reason == "SUPERSEDED" && e.Action == "STOP":
		m.toFRPC(true)
		m.act(ActCountSupersede)
		m.set(TimerProbe, m.now+SupersedePause.Milliseconds(), m.now+SupersedePause.Milliseconds())
	case e.Reason == "KEY_ROTATED" && !e.PendingKey:
		m.act(ActCloseSession)
		m.startReconnect()
	case e.Action == "USE_FRPC" && !m.modeOn:
		m.toFRPC(true)
		m.act(ActCloseAfterFRPC)
	default:
		if e.Reason == "KEY_ROTATED" {
			m.act(ActCommitRotation)
		}
		if !m.second {
			m.second = true
			m.act(ActDialSecond)
		}
	}
}

func (m *Machine) revoke(e Event) {
	if m.state != Own {
		return
	}
	switch e.Scope {
	case "APP":
		m.act(ActEndAppSessions)
	case "DEVICE", "ACCOUNT":
		m.act(ActCloseSession, ActHeartbeat)
		m.second = false
		m.startReconnect()
	}
}

func (m *Machine) hold() {
	if m.state == V1 {
		return
	}
	m.state = Hold
	m.second = false
	m.clearAll()
	m.act(ActStopTunnels)
	m.set(TimerHeartbeat, m.now+HoldPoll.Milliseconds(), m.now+HoldPoll.Milliseconds())
}

func (m *Machine) signedState(e Event) {
	m.v1Live = e.V1Live
	holds := e.DeviceStatus == "revoked" || e.DeviceStatus == "compromised" || e.AccountStatus != "active"
	clears := e.DeviceStatus == "active" && e.AccountStatus == "active"
	switch {
	case holds:
		m.hold()
	case clears && m.state == Hold:
		m.toFRPC(true)
		if m.modeOn && !m.blocked {
			m.startProbe()
		}
	case m.state == FRPC && m.frpcAuthNo && m.v1Live:
		m.toV1()
	}
}

func (m *Machine) toV1() {
	m.state = V1
	m.clearAll()
	m.act(ActUseV1)
}

func (m *Machine) frpcRefused(e Event) {
	if !e.Authenticated {
		m.act(ActIgnoredUnsigned)
		return
	}
	if m.state != FRPC {
		return
	}
	m.frpcAuthNo = true
	if m.v1Live {
		m.toV1()
		return
	}
	m.act(ActHeartbeat)
}
