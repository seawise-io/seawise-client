// Package session runs the agent's tunnel: the transport ladder (raw TLS,
// then the WebSocket carriage, then reconnecting, then HOLD) driven through
// the shared reference model, the sessions it dials, stream 0, liveness,
// Drain and Revoke, and the control-key signed flags and device state from
// stream 0 and the signed HTTPS heartbeat. One goroutine owns all of it;
// helpers only post events.
package session

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/transport"
)

// Defaults.
const (
	RouteSetDeadline = 10 * time.Second
	LocalRetry       = 30 * time.Second
	ReprobeGrace     = 30 * time.Second
	ReconnectingPoll = ladder.HoldPoll
	NetworkSettle    = 2 * time.Second
	NetworkDialEvery = 30 * time.Second
	// Drain.deadline_ms bounds from the protocol.
	minDrainMs = 1000
	maxDrainMs = 120000
	maxRetired = 2
	// rotationRetry is the first wait after a failed rotation proof.
	rotationRetry = 30 * time.Second
)

// Heartbeat budgets; variables so tests can shorten them.
var (
	// HeartbeatTimeout bounds one HTTPS heartbeat and how late its answer
	// may arrive.
	HeartbeatTimeout = 30 * time.Second
	// callTimeout bounds each stream 0 attempt.
	callTimeout = 10 * time.Second
)

// Clock is the manager's time source.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Config configures a Manager.
type Config struct {
	Dial     DialFunc
	Name     string // tunnel name, e.g. tunnel-us-east.seawise.dev
	ServerID string // canonical uuid
	// KeyID is the current device key's id, for the signed state.
	KeyID  func() string
	KeySet func() *protocol.KeySet
	// Heartbeat sends the signed heartbeat on stream 0 and over HTTPS; nil
	// sends none.
	Heartbeat *Heartbeat
	// DataDir keeps the last accepted flags ("" keeps none).
	DataDir string
	// Pending returns the pending device key of a rotation, or nil;
	// CommitRotation makes it current, only if it is still the key kid.
	Pending        func() crypto.Signer
	CommitRotation func(kid string) error
	// OnRoutes receives every applied RouteSet of the active session.
	OnRoutes func(*claims.RouteSet)
	// Network signals network changes (nil: watch the host).
	Network <-chan struct{}
	Clock   Clock
	// Rand returns a uniform value in [0, n).
	Rand   func(n int64) int64
	Logger *slog.Logger
}

// Manager is the tunnel of one agent run.
type Manager struct {
	cfg      Config
	log      *slog.Logger
	serverID []byte
	events   chan any
	done     chan struct{}
	quit     chan struct{} // closed when the loop stops reading events
	repair   chan struct{}

	statusMu sync.Mutex
	status   Status
	cur      Status // owned by the loop; published to status

	callMu sync.Mutex
	calls  map[uint32]chan *pb.DeviceResult
	callID uint32

	// Owned by the loop.
	m           *ladder.Machine
	out         ladder.Output
	t0          time.Time
	lastAt      int64
	fire        map[string]time.Time
	windows     map[string]ladder.Window
	nextID      int
	conns       map[int]*live
	active      *live
	dials       map[int]*dialing
	retired     map[int]time.Time
	localRetry  time.Time
	localCar    transport.Carriage
	pinged      bool
	pingAt      time.Time
	pingSeq     uint64
	netAt       time.Time
	lastNet     time.Time // last network change that redialled
	hbBusy      bool
	hbNonce     string
	rotNonce    string
	rotLevel    int
	rotNext     time.Time
	rotWanted   bool
	rotDeferred *ladder.Event // a revoked state waiting for the proof
	lastHB      time.Time
	stateTime   int64
	flagsGen    int64
	flagsOn     bool
	wg          sync.WaitGroup
}

type live struct {
	id         int
	conn       Conn
	info       ConnInfo
	up         bool
	routes     *claims.RouteSet
	routeVer   int64
	policyVer  uint64
	deadline   time.Time // RouteSet deadline before up
	drainUntil time.Time
	lastRx     time.Time
}

type dialing struct {
	cancel context.CancelFunc
	second bool
}

type evDial struct {
	id   int
	conn Conn
	err  error
}

type evMsg struct {
	id  int
	msg *pb.ControlMessage
}

type evClosed struct {
	id  int
	err error
}

type evRotation struct {
	nonce, kid string
	ans        Answer
	err        error
}

type evHB struct {
	nonce string
	sent  time.Time // start of the request that answered
	ans   Answer
	err   error
}

// New checks the configuration and loads the persisted flags.
func New(cfg Config) (*Manager, error) {
	if cfg.Dial == nil || cfg.KeySet == nil || cfg.KeyID == nil || cfg.Name == "" {
		return nil, errors.New("session: dial, key set, key id and name are required")
	}
	sid, err := hex.DecodeString(strings.ReplaceAll(cfg.ServerID, "-", ""))
	if err != nil || len(sid) != 16 || !claims.ValidUUID(cfg.ServerID) {
		return nil, errors.New("session: server id is not a canonical uuid")
	}
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.Rand == nil {
		cfg.Rand = cryptoRand
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	m := &Manager{cfg: cfg, log: cfg.Logger.With("component", "tunnel"), serverID: sid,
		events: make(chan any, 16), done: make(chan struct{}), quit: make(chan struct{}), repair: make(chan struct{}, 1),
		calls: map[uint32]chan *pb.DeviceResult{}, fire: map[string]time.Time{}, windows: map[string]ladder.Window{},
		conns: map[int]*live{}, dials: map[int]*dialing{}, retired: map[int]time.Time{}}
	f, err := loadFlags(cfg.DataDir)
	if err == nil && f.generation > 0 {
		err = recheckFlags(f, cfg.KeySet(), sid)
	}
	if err != nil {
		m.log.Warn("stored protocol flags ignored", "error", err)
		f = storedFlags{on: true}
	}
	m.flagsGen, m.flagsOn = f.generation, f.on
	m.cur = Status{State: ladder.Own, Carriage: "tls", FlagsGeneration: f.generation, FlagsMode: modeName(f.on)}
	m.status = m.cur
	return m, nil
}

func cryptoRand(n int64) int64 {
	if n <= 1 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int64(binary.LittleEndian.Uint64(b[:]) % uint64(n)) //nolint:gosec // G115: n > 1, result < n
}

// Status returns the last published status.
func (m *Manager) Status() Status {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	return m.status
}

// ErrNoPendingKey means no rotation is pending, so a refused proof cannot
// be a rotation the server accepted first.
var ErrNoPendingKey = errors.New("no pending device key")

type evProve struct{}

// ProveRotation asks the loop to prove the pending key now. The rotation
// is committed only on a control-key signed state naming it active.
func (m *Manager) ProveRotation() error {
	if m.cfg.Pending == nil || m.cfg.CommitRotation == nil || m.cfg.Pending() == nil {
		return ErrNoPendingKey
	}
	select {
	case m.events <- evProve{}:
		return nil
	case <-m.quit:
		return errors.New("session manager stopped")
	default:
		return errors.New("session manager busy; try again")
	}
}

// RepairNeeded records the local repair-needed fact (rotation recovery
// failed).
func (m *Manager) RepairNeeded() {
	select {
	case m.repair <- struct{}{}:
	default:
	}
}

// Run owns the tunnel until ctx ends, then closes every session.
func (m *Manager) Run(ctx context.Context) error {
	defer close(m.done)
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		close(m.quit)
		m.stopAll()
		m.wg.Wait()
		m.drain()
	}()
	netCh := m.cfg.Network
	if netCh == nil {
		netCh = WatchNetwork(ctx, m.log)
	}
	m.t0 = m.cfg.Clock.Now()
	m.lastHB = m.t0
	m.m = ladder.New(m.flagsGen, m.flagsOn)
	m.step(ctx, ladder.Event{Kind: ladder.EvStart}, nil)
	m.publish()
	for {
		var wake <-chan time.Time
		if w, ok := m.nextWake(); ok {
			wake = m.cfg.Clock.After(max(w.Sub(m.cfg.Clock.Now()), 0))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-m.events:
			m.handle(ctx, ev)
		case <-netCh:
			m.netAt = m.cfg.Clock.Now().Add(NetworkSettle)
			if !m.lastNet.IsZero() {
				m.netAt = later(m.netAt, m.lastNet.Add(NetworkDialEvery))
			}
		case <-m.repair:
			m.step(ctx, ladder.Event{Kind: ladder.EvRepair}, nil)
		case <-wake:
			m.onWake(ctx)
		}
		m.publish()
	}
}

func (m *Manager) post(ev any) {
	select {
	case m.events <- ev:
	case <-m.quit:
		if d, ok := ev.(evDial); ok && d.conn != nil {
			_ = d.conn.Close()
		}
	}
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// drain closes sessions that dials delivered after the loop stopped.
func (m *Manager) drain() {
	for {
		select {
		case ev := <-m.events:
			if d, ok := ev.(evDial); ok && d.conn != nil {
				_ = d.conn.Close()
			}
		default:
			return
		}
	}
}

func (m *Manager) at(t time.Time) int64 {
	ms := t.Sub(m.t0).Milliseconds()
	if ms < m.lastAt {
		ms = m.lastAt
	}
	m.lastAt = ms
	return ms
}

func (m *Manager) timeOf(ms int64) time.Time { return m.t0.Add(time.Duration(ms) * time.Millisecond) }

// step applies one ladder event and carries out the model's actions. src
// is the session the event concerns, if any.
func (m *Manager) step(ctx context.Context, e ladder.Event, src *live) {
	if e.At == 0 {
		e.At = m.at(m.cfg.Clock.Now())
	} else {
		e.At = m.at(m.timeOf(e.At))
	}
	prev := m.out
	o := m.m.Step(e)
	m.out = o
	m.syncTimers(o)
	if prev.State != o.State || prev.Hold != o.Hold {
		m.logTransition(prev, o, e)
	}
	probe := false
	if _, had := prev.Timers[ladder.TimerProbe]; had {
		_, still := o.Timers[ladder.TimerProbe]
		probe = !still
	}
	if e.Kind == ladder.EvDialOK && src != nil && o.State != ladder.Hold && !slices.Contains(o.Actions, ladder.ActCloseSession) {
		m.becomeActive(src)
	}
	for _, a := range o.Actions {
		m.act(ctx, a, o, src, probe)
	}
	if (o.State == ladder.Reconnecting || o.State == ladder.Hold) && m.active != nil {
		m.log.Info("tunnel session closed", "edge", m.active.info.EdgeID, "event", e.Kind)
		m.closeLive(m.active)
		m.active = nil
	}
}

func (m *Manager) logTransition(prev, o ladder.Output, e ladder.Event) {
	attrs := []any{"state", o.State, "carriage", strings.ToLower(o.Transport), "event", e.Kind}
	for _, kv := range [][2]string{{"cause", e.Cause}, {"code", e.Code}, {"reason", e.Reason}, {"scope", e.Scope}} {
		if kv[1] != "" {
			attrs = append(attrs, kv[0], kv[1])
		}
	}
	if o.Hold != "" {
		m.log.Warn("tunnel on hold: "+HoldText(o.Hold), append(attrs, "hold", o.Hold)...)
		return
	}
	m.log.Info("tunnel state", append(attrs, "from", prev.State)...)
}

// syncTimers picks a fire time inside each new window (full jitter).
func (m *Manager) syncTimers(o ladder.Output) {
	for name := range m.windows {
		if _, ok := o.Timers[name]; !ok {
			delete(m.windows, name)
			delete(m.fire, name)
		}
	}
	for name, w := range o.Timers {
		if old, ok := m.windows[name]; ok && old == w {
			continue
		}
		m.windows[name] = w
		m.fire[name] = m.timeOf(w[0] + m.cfg.Rand(w[1]-w[0]+1))
	}
}

func (m *Manager) act(ctx context.Context, a string, o ladder.Output, src *live, probe bool) {
	switch a {
	case ladder.ActDial:
		m.dial(ctx, carriageOf(o.Transport), false)
	case ladder.ActDialSecond:
		c := carriageOf(o.Transport)
		if probe {
			c = transport.TLS
		}
		m.dial(ctx, c, true)
	case ladder.ActSwitchSession:
		// handled with the session that came up (becomeActive)
	case ladder.ActCloseSession:
		if src != nil && src != m.active {
			m.closeLive(src)
		} else if m.active != nil {
			m.closeLive(m.active)
			m.active = nil
		}
	case ladder.ActSendPing:
		m.sendPing()
	case ladder.ActHeartbeat:
		m.heartbeat(ctx)
	case ladder.ActCommitRotation:
		m.proveRotation(ctx, false)
	case ladder.ActEndAppSessions:
		m.log.Info("edge revoked an app")
	case ladder.ActStopTunnels:
		m.stopAll()
	case ladder.ActCountSupersede:
		m.dropPending()
		m.cur.Supersedes++
		m.log.Warn("session superseded by another run of this device")
	case ladder.ActFlagsRollback:
		m.cur.FlagsRollbacks++
		m.log.Warn("protocol flags with an old generation refused")
	}
}

func carriageOf(t string) transport.Carriage {
	if t == ladder.WebSocket {
		return transport.WebSocket
	}
	return transport.TLS
}

// becomeActive makes a session that delivered its first RouteSet the
// active one; a previous active session is retired.
func (m *Manager) becomeActive(l *live) {
	if old := m.active; old != nil && old != l {
		until := old.drainUntil
		if until.IsZero() {
			until = m.cfg.Clock.Now().Add(ReprobeGrace)
		}
		m.retired[old.id] = until
		m.trimRetired()
	}
	m.active = l
	m.pinged = false
	l.lastRx = l.conn.LastReceived()
	m.m.SetPing(l.info.PingInterval, l.info.PingTimeout)
	m.localRetry = time.Time{}
	m.cur.LastError, m.cur.LocalHold, m.cur.LocalHoldText = "", "", ""
	if l.routes != nil && m.cfg.OnRoutes != nil {
		m.cfg.OnRoutes(l.routes)
	}
}

// trimRetired keeps at most maxRetired old sessions open, closing the
// one that would close first.
func (m *Manager) trimRetired() {
	for len(m.retired) > maxRetired {
		first, at := -1, time.Time{}
		for id, t := range m.retired {
			if first < 0 || t.Before(at) || (t.Equal(at) && id < first) {
				first, at = id, t
			}
		}
		if l := m.conns[first]; l != nil {
			m.closeLive(l)
		}
		delete(m.retired, first)
	}
}

func (m *Manager) dial(ctx context.Context, c transport.Carriage, second bool) {
	if !second {
		for id, d := range m.dials {
			d.cancel()
			delete(m.dials, id)
		}
		for _, l := range m.conns {
			if !l.up && l != m.active {
				m.closeLive(l)
			}
		}
	}
	m.nextID++
	id := m.nextID
	dctx, cancel := context.WithCancel(ctx)
	m.dials[id] = &dialing{cancel: cancel, second: second}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		conn, err := m.cfg.Dial(dctx, m.cfg.Name, c)
		m.post(evDial{id: id, conn: conn, err: err})
	}()
}

func (m *Manager) handle(ctx context.Context, ev any) {
	switch ev := ev.(type) {
	case evDial:
		m.onDial(ctx, ev)
	case evMsg:
		if l := m.conns[ev.id]; l != nil {
			m.onMessage(ctx, l, ev.msg)
		}
	case evClosed:
		if l := m.conns[ev.id]; l != nil {
			m.onClosed(ctx, l, ev.err)
		}
	case evHB:
		m.onHeartbeat(ctx, ev)
	case evRotation:
		m.onRotation(ctx, ev)
	case evProve:
		m.proveRotation(ctx, true)
	}
}

func (m *Manager) onDial(ctx context.Context, ev evDial) {
	d, current := m.dials[ev.id]
	if current {
		d.cancel()
		delete(m.dials, ev.id)
	}
	if !current {
		if ev.conn != nil {
			_ = ev.conn.Close()
		}
		return
	}
	if ev.err != nil {
		m.cur.LastError = dialReason(ev.err)
		held := m.cur.LocalHold
		m.cur.LocalHold, m.cur.LocalHoldText = "", ""
		var te *transport.Error
		if errors.As(ev.err, &te) && te.Kind == transport.Local && !d.second {
			if text, ok := localHolds[te.Reason]; ok {
				if held != te.Reason {
					m.log.Warn("tunnel on hold: "+text, "hold", te.Reason)
				}
				m.cur.LocalHold, m.cur.LocalHoldText = te.Reason, text
			} else {
				m.log.Warn("tunnel not dialled", "reason", te.Reason, "error", te)
			}
			m.localRetry = m.cfg.Clock.Now().Add(LocalRetry)
			m.localCar = carriageOf(m.out.Transport)
			return
		}
		e := ladder.Event{Kind: ladder.EvDialFailed, Cause: transport.CauseDial}
		if te != nil && te.Kind != transport.Local {
			e, _ = te.Event(0)
		}
		m.log.Info("tunnel dial failed", "carriage", strings.ToLower(m.out.Transport), "error", ev.err)
		m.step(ctx, e, nil)
		if te != nil && te.RetryAfter > 0 {
			m.retryAfter(te.RetryAfter)
		}
		return
	}
	l := &live{id: ev.id, conn: ev.conn, info: ev.conn.Info(), deadline: m.cfg.Clock.Now().Add(RouteSetDeadline)}
	m.conns[l.id] = l
	m.wg.Add(1)
	go m.read(l)
}

// retryAfter delays the next redial as an edge asked. The value is
// unsigned, so it is capped at the slow re-dial cap and jittered.
func (m *Manager) retryAfter(d time.Duration) {
	f, ok := m.fire[ladder.TimerRedial]
	if !ok {
		return
	}
	d = min(d, ladder.ReprobeCap) + time.Duration(m.cfg.Rand(ladder.RedialCap.Milliseconds()))*time.Millisecond
	if at := m.cfg.Clock.Now().Add(d); f.Before(at) {
		m.fire[ladder.TimerRedial] = at
	}
}

func dialReason(err error) string {
	var te *transport.Error
	if errors.As(err, &te) {
		if te.Reason != "" {
			return te.Kind.String() + ": " + te.Reason
		}
		return te.Kind.String()
	}
	return "dial failed"
}

func (m *Manager) read(l *live) {
	defer m.wg.Done()
	for {
		msg, err := l.conn.Next()
		if err != nil {
			m.post(evClosed{id: l.id, err: err})
			return
		}
		if r := msg.GetDeviceResult(); r != nil {
			m.deliver(r)
			continue
		}
		m.post(evMsg{id: l.id, msg: msg})
	}
}

func (m *Manager) closeLive(l *live) {
	delete(m.conns, l.id)
	delete(m.retired, l.id)
	_ = l.conn.Close()
}

// dropPending cancels dials in flight and closes sessions not yet up, so
// nothing comes up during a pause.
func (m *Manager) dropPending() {
	for id, d := range m.dials {
		d.cancel()
		delete(m.dials, id)
	}
	for _, l := range m.conns {
		if !l.up && l != m.active {
			m.closeLive(l)
		}
	}
}

func (m *Manager) stopAll() {
	for id, d := range m.dials {
		d.cancel()
		delete(m.dials, id)
	}
	for _, l := range m.conns {
		m.closeLive(l)
	}
	m.active = nil
	m.localRetry = time.Time{}
}

// fail ends a session on a protocol error.
func (m *Manager) fail(ctx context.Context, l *live, why string) {
	m.log.Warn("tunnel session closed", "reason", why, "edge", l.info.EdgeID)
	m.closeLive(l)
	m.lost(ctx, l)
}

func (m *Manager) onClosed(ctx context.Context, l *live, err error) {
	if _, retired := m.retired[l.id]; !retired && l == m.active {
		m.log.Info("tunnel session ended", "edge", l.info.EdgeID, "error", err)
	}
	m.closeLive(l)
	m.lost(ctx, l)
}

func (m *Manager) lost(ctx context.Context, l *live) {
	switch {
	case l == m.active:
		m.active = nil
		m.step(ctx, ladder.Event{Kind: ladder.EvSessionLost}, l)
	case !l.up:
		m.step(ctx, ladder.Event{Kind: ladder.EvDialFailed, Cause: transport.CauseAckSignature}, l)
	}
}

func (m *Manager) onMessage(ctx context.Context, l *live, msg *pb.ControlMessage) {
	_, retired := m.retired[l.id]
	switch b := msg.GetBody().(type) {
	case *pb.ControlMessage_RouteSet:
		if retired {
			return
		}
		m.routeSet(ctx, l, b.RouteSet)
	case *pb.ControlMessage_PolicyVersion:
		if b.PolicyVersion.GetVersion() <= l.policyVer {
			m.fail(ctx, l, "policy_version")
			return
		}
		l.policyVer = b.PolicyVersion.GetVersion()
		if f := b.PolicyVersion.GetFlags(); f != "" {
			m.flags(ctx, f, "stream0")
		}
	case *pb.ControlMessage_Drain:
		d := b.Drain
		ms := min(max(d.GetDeadlineMs(), minDrainMs), maxDrainMs)
		l.drainUntil = m.cfg.Clock.Now().Add(time.Duration(ms) * time.Millisecond)
		if l != m.active || retired {
			return
		}
		action := "RECONNECT"
		if d.GetAction() == pb.DrainAction_HOLD {
			action = "HOLD"
		}
		pending := m.cfg.Pending != nil && m.cfg.Pending() != nil
		m.log.Info("edge drains the session", "reason", d.GetReason().String(), "action", action)
		m.step(ctx, ladder.Event{Kind: ladder.EvDrain, Reason: d.GetReason().String(), Action: action, PendingKey: pending}, l)
	case *pb.ControlMessage_Revoke:
		if l != m.active || retired {
			return
		}
		m.log.Warn("edge revoked", "scope", b.Revoke.GetScope().String())
		m.step(ctx, ladder.Event{Kind: ladder.EvRevoke, Scope: b.Revoke.GetScope().String()}, l)
	case *pb.ControlMessage_MinVersion:
		m.cur.MinVersion = b.MinVersion.GetMinAgentVersion()
		m.log.Info("edge announced a minimum version", "version", m.cur.MinVersion)
	case *pb.ControlMessage_Error:
		m.log.Warn("edge reported an error", "code", b.Error.GetCode().String())
		if b.Error.GetCode() == pb.ErrorCode_PROTOCOL {
			m.fail(ctx, l, "edge_protocol_error")
		}
	case *pb.ControlMessage_Pong:
	default:
		m.fail(ctx, l, "unexpected_message")
	}
}

func (m *Manager) routeSet(ctx context.Context, l *live, rs *pb.RouteSet) {
	ks := m.cfg.KeySet()
	set, err := verifyRouteSet(rs, ks, m.cfg.ServerID, l.info, l.routeVer)
	if err != nil {
		m.log.Warn("RouteSet refused", "error", err)
		m.fail(ctx, l, "routeset")
		return
	}
	if st := rs.GetSignedTime(); st != "" {
		t, err := protocol.VerifySignedTime(st, ks, m.cfg.ServerID, claims.TimeNonce(l.info.TimeNonce))
		if err != nil {
			m.log.Warn("signed time in RouteSet ignored", "error", err)
		} else {
			m.cur.SignedTime = max(m.cur.SignedTime, t.Time)
		}
	}
	l.routeVer, l.routes = set.Version, set
	if err := l.conn.Send(&pb.ControlMessage{Body: &pb.ControlMessage_RouteSetAck{RouteSetAck: &pb.RouteSetAck{Version: uint64(set.Version)}}}); err != nil { //nolint:gosec // G115: a verified safe integer
		m.fail(ctx, l, "routeset_ack")
		return
	}
	if l.up {
		if l == m.active && m.cfg.OnRoutes != nil {
			m.cfg.OnRoutes(set)
		}
		return
	}
	l.up = true
	m.log.Info("tunnel session up", "edge", l.info.EdgeID, "carriage", l.info.Carriage.String(), "routes", len(set.Routes))
	m.step(ctx, ladder.Event{Kind: ladder.EvDialOK}, l)
}

func (m *Manager) sendPing() {
	l := m.active
	if l == nil {
		return
	}
	m.pingSeq++
	m.pinged, m.pingAt = true, m.cfg.Clock.Now()
	if err := l.conn.Send(&pb.ControlMessage{Body: &pb.ControlMessage_Ping{Ping: &pb.Ping{Nonce: m.pingSeq}}}); err != nil {
		m.log.Info("ping not sent", "error", err)
	}
}

// flags applies a flags document from either carrier. The same generation
// again is the same document and is ignored.
func (m *Manager) flags(ctx context.Context, doc, from string) {
	f, on, err := verifyFlags(doc, m.cfg.KeySet(), m.serverID)
	if err != nil {
		m.log.Warn("protocol flags refused", "from", from, "error", err)
		return
	}
	if f.Generation == m.flagsGen {
		return
	}
	if f.Generation > m.flagsGen {
		if err := saveFlags(m.cfg.DataDir, f.Generation, on, doc); err != nil {
			m.log.Warn("store protocol flags", "error", err)
		}
		m.flagsGen, m.flagsOn = f.Generation, on
		m.cur.FlagsGeneration, m.cur.FlagsMode = f.Generation, modeName(on)
		m.log.Info("protocol flags accepted", "from", from, "generation", f.Generation, "mode", modeName(on))
	}
	m.step(ctx, ladder.Event{Kind: ladder.EvFlags, Generation: f.Generation, Mode: modeName(on)}, nil)
}

func (m *Manager) heartbeat(ctx context.Context) {
	if m.hbBusy || m.cfg.Heartbeat == nil {
		return
	}
	nonce := newID()
	m.hbBusy, m.hbNonce, m.lastHB = true, nonce, m.cfg.Clock.Now()
	var c Conn
	if m.active != nil {
		c = m.active.conn
	}
	hb := m.cfg.Heartbeat
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		var ans Answer
		err := errors.New("no session")
		sent := m.cfg.Clock.Now()
		if c != nil {
			sctx, cancel := context.WithTimeout(ctx, 2*callTimeout)
			ans, err = m.stream0Heartbeat(sctx, hb, c, nonce)
			cancel()
			if err != nil {
				m.log.Info("heartbeat on stream 0 failed; using HTTPS", "error", err)
			}
		}
		if err != nil {
			sent = m.cfg.Clock.Now()
			hctx, cancel := context.WithTimeout(ctx, HeartbeatTimeout)
			ans, err = hb.HTTPS(hctx, nonce, c != nil)
			cancel()
		}
		m.post(evHB{nonce: nonce, sent: sent, ans: ans, err: err})
	}()
}

// proveRotation runs a signed heartbeat proved by the pending key. The
// edge's KEY_ROTATED is unsigned, so the rotation is committed only when
// the control-key signed state names the pending key as active. A failed
// proof is retried with backoff while the key stays pending; force skips
// the backoff wait (a signed revoked state is about to hold the agent).
func (m *Manager) proveRotation(ctx context.Context, force bool) {
	if m.rotNonce != "" || m.cfg.Pending == nil || m.cfg.CommitRotation == nil || m.cfg.Heartbeat == nil {
		return
	}
	if !force && m.cfg.Clock.Now().Before(m.rotNext) {
		m.rotWanted = true
		return
	}
	key := m.cfg.Pending()
	if key == nil {
		m.rotWanted = false
		return
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return
	}
	nonce, kid, hb := newID(), protocol.KeyID(pub), m.cfg.Heartbeat
	m.rotNonce, m.rotWanted = nonce, false
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		hctx, cancel := context.WithTimeout(ctx, HeartbeatTimeout)
		defer cancel()
		ans, err := hb.HTTPSAs(hctx, key, nonce, true)
		m.post(evRotation{nonce: nonce, kid: kid, ans: ans, err: err})
	}()
}

func (m *Manager) onRotation(ctx context.Context, ev evRotation) {
	if ev.nonce != m.rotNonce {
		return
	}
	m.rotNonce = ""
	st, err := m.provedState(ev)
	if err == nil {
		err = m.cfg.CommitRotation(ev.kid)
	}
	if err != nil {
		m.rotationFailed(ctx, err)
		return
	}
	m.rotLevel, m.rotNext, m.rotDeferred = 0, time.Time{}, nil
	m.log.Info("pending device key confirmed and committed")
	if ev.ans.Flags != "" {
		m.flags(ctx, ev.ans.Flags, "heartbeat")
	}
	// The proof is the signed state of the key now current.
	m.step(ctx, ladder.Event{Kind: ladder.EvSignedState, DeviceStatus: st.DeviceStatus, AccountStatus: st.AccountStatus}, nil)
	m.redialNow()
}

func (m *Manager) provedState(ev evRotation) (*claims.SignedState, error) {
	if ev.err != nil {
		return nil, ev.err
	}
	st, err := verifyState(ev.ans.State, m.cfg.KeySet(), m.cfg.ServerID, ev.kid, ev.nonce)
	if err != nil {
		return nil, err
	}
	if !st.Clears() {
		return nil, errors.New("pending key is not active")
	}
	return st, nil
}

// rotationFailed keeps the current key, schedules the next proof and
// applies a revoked state that waited for this proof.
func (m *Manager) rotationFailed(ctx context.Context, err error) {
	m.log.Warn("pending device key not proved; keeping the current key", "error", err)
	m.rotLevel++
	d := min(rotationRetry<<min(m.rotLevel-1, 16), ladder.ReprobeCap)
	m.rotNext = m.cfg.Clock.Now().Add(d + time.Duration(m.cfg.Rand(rotationRetry.Milliseconds()))*time.Millisecond)
	m.rotWanted = m.cfg.Pending() != nil
	if e := m.rotDeferred; e != nil {
		m.rotDeferred = nil
		m.step(ctx, *e, nil)
	}
}

// redialNow fires a pending dial or redial timer at once; the window
// always starts at the time it was set.
func (m *Manager) redialNow() {
	now := m.cfg.Clock.Now()
	for _, name := range []string{ladder.TimerDial, ladder.TimerRedial} {
		if _, ok := m.fire[name]; ok {
			m.fire[name] = now
		}
	}
}

func (m *Manager) stream0Heartbeat(ctx context.Context, hb *Heartbeat, c Conn, nonce string) (Answer, error) {
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	for attempt := 0; attempt < 2; attempt++ {
		id, ch := m.register()
		call, err := hb.Call(id, key, nonce, true)
		if err != nil {
			m.unregister(id)
			return Answer{}, err
		}
		if err := c.Send(&pb.ControlMessage{Body: &pb.ControlMessage_DeviceCall{DeviceCall: call}}); err != nil {
			m.unregister(id)
			return Answer{}, err
		}
		var r *pb.DeviceResult
		select {
		case r = <-ch:
		case <-ctx.Done():
			m.unregister(id)
			return Answer{}, ctx.Err()
		case <-time.After(callTimeout):
			m.unregister(id)
			return Answer{}, errors.New("heartbeat call timed out")
		}
		ans, retry, err := hb.Result(r)
		if !retry {
			return ans, err
		}
	}
	return Answer{}, errors.New("heartbeat call: nonce refused twice")
}

func (m *Manager) register() (uint32, chan *pb.DeviceResult) {
	m.callMu.Lock()
	defer m.callMu.Unlock()
	m.callID = m.callID%(1<<31-1) + 1
	ch := make(chan *pb.DeviceResult, 1)
	m.calls[m.callID] = ch
	return m.callID, ch
}

func (m *Manager) unregister(id uint32) {
	m.callMu.Lock()
	delete(m.calls, id)
	m.callMu.Unlock()
}

func (m *Manager) deliver(r *pb.DeviceResult) {
	m.callMu.Lock()
	ch, ok := m.calls[r.GetCallId()]
	delete(m.calls, r.GetCallId())
	m.callMu.Unlock()
	if ok {
		ch <- r
	}
}

func (m *Manager) onHeartbeat(ctx context.Context, ev evHB) {
	if ev.nonce != m.hbNonce {
		return
	}
	m.hbBusy = false
	if ev.err != nil {
		m.log.Warn("signed heartbeat failed", "error", ev.err)
		return
	}
	if m.cfg.Clock.Now().Sub(ev.sent) > HeartbeatTimeout {
		m.log.Warn("signed heartbeat answer arrived too late")
		return
	}
	ks := m.cfg.KeySet()
	st, err := verifyState(ev.ans.State, ks, m.cfg.ServerID, m.cfg.KeyID(), ev.nonce)
	if err != nil {
		m.log.Warn("signed state refused", "error", err)
		return
	}
	if ev.ans.Flags != "" {
		m.flags(ctx, ev.ans.Flags, "heartbeat")
	}
	if st.Time < m.stateTime {
		m.log.Warn("signed state older than the last one ignored")
		return
	}
	m.stateTime = st.Time
	m.cur.SignedTime = max(m.cur.SignedTime, st.Time)
	if st.DeviceStatus == claims.DeviceRevoked && m.cfg.Pending != nil && m.cfg.Pending() != nil {
		// The server may have accepted the rotation already: prove the
		// pending key before holding on the old key's revocation.
		e := ladder.Event{Kind: ladder.EvSignedState, DeviceStatus: st.DeviceStatus, AccountStatus: st.AccountStatus}
		m.rotDeferred = &e
		m.proveRotation(ctx, true)
		if m.rotNonce != "" {
			return
		}
		m.rotDeferred = nil
	}
	m.step(ctx, ladder.Event{Kind: ladder.EvSignedState, DeviceStatus: st.DeviceStatus, AccountStatus: st.AccountStatus}, nil)
}

func (m *Manager) nextWake() (time.Time, bool) {
	var w time.Time
	add := func(t time.Time) {
		if !t.IsZero() && (w.IsZero() || t.Before(w)) {
			w = t
		}
	}
	for _, t := range m.fire {
		add(t)
	}
	if l := m.active; l != nil {
		if m.pinged {
			add(m.pingAt.Add(l.info.PingTimeout))
		} else {
			add(l.lastRx.Add(l.info.PingInterval))
		}
	}
	for _, t := range m.retired {
		add(t)
	}
	for _, l := range m.conns {
		if !l.up {
			add(l.deadline)
		}
	}
	add(m.localRetry)
	add(m.netAt)
	if m.rotWanted && m.rotNonce == "" {
		add(m.rotNext)
	}
	if m.out.State == ladder.Reconnecting && m.cfg.Heartbeat != nil {
		add(m.lastHB.Add(ReconnectingPoll))
	}
	return w, !w.IsZero()
}

func (m *Manager) onWake(ctx context.Context) {
	now := m.cfg.Clock.Now()
	if !m.netAt.IsZero() && !m.netAt.After(now) {
		m.netAt = time.Time{}
		m.log.Info("network changed")
		if m.out.State == ladder.Reconnecting {
			m.lastNet = now
		}
		m.step(ctx, ladder.Event{Kind: ladder.EvNetwork}, nil)
	}
	for _, name := range []string{ladder.TimerDial, ladder.TimerRedial, ladder.TimerProbe, ladder.TimerHeartbeat} {
		if t, ok := m.fire[name]; ok && !t.After(now) {
			delete(m.fire, name)
			m.step(ctx, ladder.Event{Kind: ladder.EvTimer, Reason: name}, nil)
		}
	}
	if l := m.active; l != nil {
		if rx := l.conn.LastReceived(); rx.After(l.lastRx) {
			l.lastRx = rx
			m.pinged = false
			m.step(ctx, ladder.Event{At: max(rx.Sub(m.t0).Milliseconds(), 1), Kind: ladder.EvReceived}, l)
		}
		due := l.lastRx.Add(l.info.PingInterval)
		if m.pinged {
			due = m.pingAt.Add(l.info.PingTimeout)
		}
		if !due.After(now) {
			if m.pinged {
				m.log.Warn("tunnel session silent", "edge", l.info.EdgeID)
			}
			m.step(ctx, ladder.Event{Kind: ladder.EvTick}, l)
		}
	}
	for id, t := range m.retired {
		if !t.After(now) {
			if l := m.conns[id]; l != nil {
				m.closeLive(l)
			}
			delete(m.retired, id)
		}
	}
	for _, l := range m.conns {
		if !l.up && !l.deadline.After(now) {
			m.log.Warn("no RouteSet after HelloAck", "edge", l.info.EdgeID)
			m.closeLive(l)
			m.lost(ctx, l)
		}
	}
	if m.rotWanted && m.rotNonce == "" && !m.rotNext.After(now) {
		m.proveRotation(ctx, false)
	}
	if !m.localRetry.IsZero() && !m.localRetry.After(now) {
		m.localRetry = time.Time{}
		m.dial(ctx, m.localCar, false)
	}
	if m.out.State == ladder.Reconnecting && !m.lastHB.Add(ReconnectingPoll).After(now) {
		m.lastHB = now
		m.heartbeat(ctx)
	}
}

func (m *Manager) publish() {
	s := m.cur
	s.State, s.Hold, s.HoldText = m.out.State, m.out.Hold, HoldText(m.out.Hold)
	s.Carriage = carriageOf(m.out.Transport).String()
	s.Up = m.active != nil
	s.Edge, s.SessionID, s.Proxied, s.LastKnown = "", "", false, false
	if l := m.active; l != nil {
		s.Edge, s.SessionID = l.info.EdgeID, base64.RawURLEncoding.EncodeToString(l.info.SessionID)
		s.Proxied, s.LastKnown, s.Carriage = l.info.Proxied, l.info.LastKnown, l.info.Carriage.String()
	}
	s.NextDial = time.Time{}
	for _, name := range []string{ladder.TimerDial, ladder.TimerRedial} {
		if t, ok := m.fire[name]; ok {
			s.NextDial = t
		}
	}
	if !m.localRetry.IsZero() {
		s.NextDial = m.localRetry
	}
	m.statusMu.Lock()
	if s.State != m.status.State || s.Hold != m.status.Hold || m.status.Since.IsZero() {
		s.Since = m.cfg.Clock.Now()
	}
	m.status = s
	m.statusMu.Unlock()
	m.cur.Since = s.Since
}
