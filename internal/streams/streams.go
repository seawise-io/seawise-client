// Package streams serves the data streams of tunnel sessions: it reads the
// stream header, maps the app id through the session's signed RouteSet,
// checks the visitor token, replies, and carries exactly one HTTP/1.1
// request to the app through the forwarder and the target policy.
package streams

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/caps"
	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
	"github.com/seawise/client/internal/visitor"
)

// Defaults.
const (
	DefaultMaxStreams  = int(caps.DefaultAgentMaxStreams)
	DefaultHeadTimeout = caps.StreamOpenTimeout
	DefaultIdleTimeout = caps.StreamIdleTimeout
	// DefaultCloseWait bounds the wait for the app after the edge ended an
	// upgraded stream.
	DefaultCloseWait = 5 * time.Second
	replyTimeout     = 5 * time.Second
	logEvery         = time.Minute
)

// CodeNoSignedTime is the decision for a stream that needs a token while
// the clock has no signed time.
const CodeNoSignedTime = "no_signed_time"

// Config configures a Server.
type Config struct {
	Gate *visitor.Gate
	// Targets returns the stored apps.
	Targets func() []store.Target
	// Dial connects to an app's target by local id (the forwarder).
	Dial func(ctx context.Context, localID string) (*forwarder.Upstream, error)
	// Record, if set, receives one entry per stream that reached the gate.
	Record func(accesslog.Entry)
	// ClockReady reports whether signed time corrects the gate's clock;
	// until it does, enforce refuses every stream that needs a token.
	ClockReady  func() bool
	MaxStreams  int
	HeadTimeout time.Duration
	IdleTimeout time.Duration
	CloseWait   time.Duration
	Now         func() time.Time
	Logger      *slog.Logger
}

// Server serves data streams; one serves every session of the agent.
type Server struct {
	cfg    Config
	log    *slog.Logger
	mu     sync.Mutex
	counts map[string]uint64
	active atomic.Int64
	resets atomic.Uint64
	noTime atomic.Uint64
	// lastNoTime throttles the no-signed-time log (under mu).
	lastNoTime time.Time
}

// Status is the stream count per reply code, streams in progress, streams
// reset, and the visitor gate's mode and counts.
type Status struct {
	Active  int64             `json:"active"`
	Replies map[string]uint64 `json:"replies"`
	Resets  uint64            `json:"resets"`
	// NoSignedTime counts streams that needed a token before signed time.
	NoSignedTime uint64         `json:"no_signed_time"`
	Visitor      visitor.Status `json:"visitor"`
}

// New checks the configuration.
func New(cfg Config) (*Server, error) {
	if cfg.Gate == nil || cfg.Targets == nil || cfg.Dial == nil {
		return nil, errors.New("streams: gate, targets and dial are required")
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = DefaultMaxStreams
	}
	if cfg.HeadTimeout <= 0 {
		cfg.HeadTimeout = DefaultHeadTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.CloseWait <= 0 {
		cfg.CloseWait = DefaultCloseWait
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, log: cfg.Logger.With("component", "streams"), counts: map[string]uint64{}}, nil
}

// Status returns a copy of the counters.
func (s *Server) Status() Status {
	s.mu.Lock()
	c := maps.Clone(s.counts)
	s.mu.Unlock()
	return Status{Active: s.active.Load(), Replies: c, Resets: s.resets.Load(), NoSignedTime: s.noTime.Load(), Visitor: s.cfg.Gate.Status()}
}

// stream is the part of a yamux stream the handler uses.
type stream interface {
	io.ReadWriter
	CloseWrite() error
	Close() error
	Reset() error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Serve accepts the session's data streams until the session or ctx ends,
// then resets the streams in progress and returns once they have ended.
func (s *Server) Serve(ctx context.Context, ds session.DataSession) {
	if ds.Mux == nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	defer context.AfterFunc(ctx, func() { _ = ds.Mux.Close() })()
	limit := s.cfg.MaxStreams
	if ds.MaxStreams > 0 {
		limit = min(limit, ds.MaxStreams)
	}
	sem := make(chan struct{}, limit)
	reg := newRegistry()
	if ds.Ended != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ds.Ended.C():
					reg.end(ds.Ended.Take(), routesVersion(ds))
				}
			}
		}()
	}
	for {
		st, err := ds.Mux.AcceptStream()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			s.refuse(st, pb.ReplyCode_AGENT_BUSY)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(ctx, st, ds, reg)
		}()
	}
}

func (s *Server) count(code pb.ReplyCode) {
	s.mu.Lock()
	s.counts[code.String()]++
	s.mu.Unlock()
}

func (s *Server) reset(st stream) {
	s.resets.Add(1)
	_ = st.Reset()
}

// reply writes the reply frame.
func (s *Server) reply(st stream, code pb.ReplyCode) error {
	s.count(code)
	f, err := wire.AppendStreamReply(nil, code)
	if err != nil {
		return err
	}
	_ = st.SetWriteDeadline(time.Now().Add(replyTimeout))
	_, err = st.Write(f)
	_ = st.SetWriteDeadline(time.Time{})
	return err
}

// refuse replies a refusal, then closes the write side and discards what
// the edge sends.
func (s *Server) refuse(st stream, code pb.ReplyCode) {
	if s.reply(st, code) != nil {
		s.reset(st)
		return
	}
	_ = st.Close()
}

func uuidText(b []byte) string {
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func route(rs *claims.RouteSet, app string) (claims.Route, bool) {
	if rs == nil {
		return claims.Route{}, false
	}
	for _, r := range rs.Routes {
		if r.AppID == app {
			return r, true
		}
	}
	return claims.Route{}, false
}

// target is the one enabled app stored for the server app id.
func (s *Server) target(app string) (store.Target, bool) {
	var out store.Target
	n := 0
	for _, t := range s.cfg.Targets() {
		if !t.Disabled && strings.EqualFold(t.ServerServiceID, app) {
			out = t
			n++
		}
	}
	return out, n == 1
}

func peer(ip []byte) string {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	return a.Unmap().String()
}

// header reads the stream header within the head timeout; ok is false
// when the stream was already answered or reset.
func (s *Server) header(st stream, negotiated []string) (*pb.StreamHeader, bool) {
	_ = st.SetReadDeadline(time.Now().Add(s.cfg.HeadTimeout))
	h, err := wire.ReadStreamHeader(st, negotiated)
	_ = st.SetReadDeadline(time.Time{})
	if err == nil {
		return h, true
	}
	switch wire.CodeOf(err) {
	case "", wire.CodeTruncated, wire.CodeTimeout:
		s.reset(st)
	default:
		s.refuse(st, pb.ReplyCode_BAD_HEADER)
	}
	return nil, false
}

func (s *Server) handle(ctx context.Context, st stream, ds session.DataSession, reg *registry) {
	s.active.Add(1)
	defer s.active.Add(-1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(ctx, func() { _ = st.Reset() })()
	h, ok := s.header(st, ds.Capabilities)
	if !ok {
		return
	}
	app := uuidText(h.AppId)
	var routes *claims.RouteSet
	if ds.Routes != nil {
		routes = ds.Routes()
	}
	rt, ok := route(routes, app)
	if ok {
		e := reg.add(app, routes.Version, cancel)
		if ok = e != nil; ok {
			defer reg.remove(app, e)
		}
	}
	if !ok {
		s.refuse(st, pb.ReplyCode_UNKNOWN_APP)
		return
	}
	t, found := s.target(app)
	d := s.cfg.Gate.Check(visitor.Request{AppID: app, Public: rt.Public && found && t.ServerPublic,
		Token: h.VisitorToken, StaleOk: h.StaleOkUntil})
	if d.Code != visitor.CodePublic && s.cfg.ClockReady != nil && !s.cfg.ClockReady() {
		d = s.noSignedTime(d, app)
	}
	start := s.cfg.Now()
	e := accesslog.Entry{Time: start, App: t.LocalID, Peer: peer(h.ClientIp), Decision: d.Code, Session: d.Session}
	if found {
		e.Target = net.JoinHostPort(strings.Trim(t.Host, "[]"), strconv.Itoa(t.Port))
	}
	if !d.Allow {
		s.refuse(st, d.Reply())
		if found {
			e.Result = accesslog.ResultDenied
			s.record(e, start)
		}
		return
	}
	if !found {
		s.refuse(st, pb.ReplyCode_TARGET_UNAVAILABLE)
		return
	}
	up, err := s.cfg.Dial(ctx, t.LocalID)
	if err != nil {
		code, result := pb.ReplyCode_TARGET_UNAVAILABLE, accesslog.ResultUnreachable
		switch {
		case errors.Is(err, forwarder.ErrBusy):
			code, result = pb.ReplyCode_AGENT_BUSY, accesslog.ResultBusy
		case errors.Is(err, forwarder.ErrNoApp), errors.Is(err, targetpolicy.ErrRefused):
			result = accesslog.ResultRefused
		}
		s.refuse(st, code)
		e.Result = result
		s.record(e, start)
		return
	}
	defer up.Close()
	e.Target = up.Target()
	if s.reply(st, d.Reply()) != nil {
		s.reset(st)
		e.Result = accesslog.ResultOK
		s.record(e, start)
		return
	}
	x := newExchange(s, st, up)
	e.Result = x.run()
	e.BytesIn, e.BytesOut = x.in.Load(), x.out.Load()
	s.record(e, start)
}

func (s *Server) record(e accesslog.Entry, start time.Time) {
	if s.cfg.Record == nil {
		return
	}
	e.DurationMS = s.cfg.Now().Sub(start).Milliseconds()
	s.cfg.Record(e)
}

func routesVersion(ds session.DataSession) int64 {
	if ds.Routes == nil {
		return 0
	}
	if rs := ds.Routes(); rs != nil {
		return rs.Version
	}
	return 0
}

// registry is one session's streams in progress per app, and the apps
// ended until the next RouteSet version.
type registry struct {
	mu      sync.Mutex
	active  map[string]map[*entry]struct{}
	revoked map[string]int64
}

type entry struct{ cancel context.CancelFunc }

func newRegistry() *registry {
	return &registry{active: map[string]map[*entry]struct{}{}, revoked: map[string]int64{}}
}

// add registers a stream of app under RouteSet version; nil when the app
// was ended at that version or a later one.
func (r *registry) add(app string, version int64, cancel context.CancelFunc) *entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.revoked[app]; ok && v >= version {
		return nil
	}
	if r.active[app] == nil {
		r.active[app] = map[*entry]struct{}{}
	}
	e := &entry{cancel: cancel}
	r.active[app][e] = struct{}{}
	return e
}

func (r *registry) remove(app string, e *entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.active[app], e)
	if len(r.active[app]) == 0 {
		delete(r.active, app)
	}
}

// end resets the apps' streams and refuses new ones until the RouteSet
// version changes.
func (r *registry) end(apps []string, version int64) {
	r.mu.Lock()
	var cancels []context.CancelFunc
	for _, app := range apps {
		r.revoked[app] = version
		for e := range r.active[app] {
			cancels = append(cancels, e.cancel)
		}
	}
	r.mu.Unlock()
	for _, c := range cancels {
		c()
	}
}

// noSignedTime refuses in enforce a stream that needs a token while the
// clock has no signed time; observe only counts and logs it.
func (s *Server) noSignedTime(d visitor.Decision, app string) visitor.Decision {
	s.noTime.Add(1)
	s.mu.Lock()
	logIt := time.Since(s.lastNoTime) >= logEvery
	if logIt {
		s.lastNoTime = time.Now()
	}
	s.mu.Unlock()
	if d.Mode == visitor.Enforce {
		if logIt {
			s.log.Warn("visitor refused: no signed time yet", "app", app)
		}
		return visitor.Decision{Code: CodeNoSignedTime, Mode: d.Mode}
	}
	if logIt {
		s.log.Info("visitor token checked without signed time", "app", app)
	}
	return d
}
