// Package forwarder runs one loopback listener per app. frpc connects to it
// instead of to the app, and every connection is dialled to the real target
// through the target policy, which checks the address actually connected to.
// It passes bytes through unchanged and never logs or inspects payloads.
package forwarder

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/seawise/client/internal/targetpolicy"
)

const (
	DefaultMaxConns    = 64
	DefaultIdleTimeout = 5 * time.Minute
	DefaultDialTimeout = 10 * time.Second
	refusalLogEvery    = time.Minute
)

type App struct {
	ID   string
	Host string
	Port int
	Rule targetpolicy.Rule
}

func (a App) same(b App) bool {
	return a.ID == b.ID && a.Host == b.Host && a.Port == b.Port && a.Rule.Host == b.Rule.Host &&
		a.Rule.Grandfathered == b.Rule.Grandfathered && slices.Equal(a.Rule.Grants, b.Rule.Grants)
}

type Config struct {
	Gateways    []netip.Addr
	Resolve     targetpolicy.Resolver
	MaxConns    int
	IdleTimeout time.Duration
	DialTimeout time.Duration
	Logger      *slog.Logger
}

type Forwarder struct {
	cfg  Config
	log  *slog.Logger
	mu   sync.Mutex
	apps map[string]*listener
}

func New(cfg Config) *Forwarder {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Forwarder{cfg: cfg, log: cfg.Logger.With("component", "forwarder"), apps: map[string]*listener{}}
}

// Sync makes the running listeners match apps and returns each app's
// loopback port. An app whose target or grants changed gets a new listener;
// the old one and all its connections are closed. Apps that cannot listen
// are left out of the result, so they are not tunnelled.
func (f *Forwarder) Sync(apps []App) map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := map[string]App{}
	for _, a := range apps {
		want[a.ID] = a
	}
	for id, l := range f.apps {
		if a, ok := want[id]; !ok || !a.same(l.app) {
			l.close()
			delete(f.apps, id)
		}
	}
	out := map[string]int{}
	for _, a := range apps {
		l, ok := f.apps[a.ID]
		if !ok {
			var err error
			if l, err = f.start(a); err != nil {
				f.log.Warn("app listener failed", "local_id", a.ID, "error", err)
				continue
			}
			f.apps[a.ID] = l
		}
		out[a.ID] = l.port
	}
	return out
}

// Close stops every listener and connection.
func (f *Forwarder) Close() { f.Sync(nil) }

func (f *Forwarder) listeners() []*listener {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*listener{}
	for _, l := range f.apps {
		out = append(out, l)
	}
	return out
}

type listener struct {
	f     *Forwarder
	app   App
	ln    net.Listener
	port  int
	sem   chan struct{}
	ctx   context.Context
	stop  context.CancelFunc
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	// lastRefusal throttles refusal logs.
	lastRefusal time.Time
}

func (f *Forwarder) start(a App) (*listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{f: f, app: a, ln: ln, port: ln.Addr().(*net.TCPAddr).Port, sem: make(chan struct{}, f.cfg.MaxConns),
		ctx: ctx, stop: cancel, conns: map[net.Conn]struct{}{}}
	go l.serve()
	return l, nil
}

func (l *listener) close() {
	l.stop()
	_ = l.ln.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.conns {
		_ = c.Close()
	}
}

func (l *listener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx.Err() != nil {
		return false
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *listener) untrack(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
	_ = c.Close()
}

func (l *listener) serve() {
	delay := 5 * time.Millisecond
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || l.ctx.Err() != nil {
				return
			}
			time.Sleep(delay)
			delay = min(delay*2, time.Second)
			continue
		}
		delay = 5 * time.Millisecond
		select {
		case l.sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-l.sem }()
			l.handle(c)
		}()
	}
}

func (l *listener) handle(in net.Conn) {
	if !l.track(in) {
		_ = in.Close()
		return
	}
	defer l.untrack(in)
	out, err := l.dial()
	if err != nil {
		l.refusal(err)
		return
	}
	if !l.track(out) {
		_ = out.Close()
		return
	}
	defer l.untrack(out)
	idle := l.f.cfg.IdleTimeout
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(out, in, idle) }()
	go func() { defer wg.Done(); pipe(in, out, idle) }()
	wg.Wait()
}

// dial resolves the target and connects to the first address the policy
// accepts. The policy check runs in the dialer's Control hook.
func (l *listener) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(l.ctx, l.f.cfg.DialTimeout)
	defer cancel()
	addrs, err := targetpolicy.ResolveHost(ctx, l.f.cfg.Resolve, l.app.Host)
	if err != nil {
		return nil, err
	}
	d := targetpolicy.Dialer(&net.Dialer{Timeout: l.f.cfg.DialTimeout, KeepAlive: 30 * time.Second}, l.app.Rule, l.f.cfg.Gateways)
	var firstErr error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.Unmap().String(), strconv.Itoa(l.app.Port)))
		if err == nil {
			return c, nil
		}
		if firstErr == nil || errors.Is(err, targetpolicy.ErrRefused) {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("host did not resolve")
	}
	return nil, firstErr
}

func (l *listener) refusal(err error) {
	l.mu.Lock()
	now := time.Now()
	logIt := now.Sub(l.lastRefusal) >= refusalLogEvery
	if logIt {
		l.lastRefusal = now
	}
	l.mu.Unlock()
	if !logIt {
		return
	}
	if errors.Is(err, targetpolicy.ErrRefused) {
		l.f.log.Warn("connection to app refused by target policy", "local_id", l.app.ID, "reason", err.Error())
	} else {
		l.f.log.Info("app unreachable", "local_id", l.app.ID, "error", err.Error())
	}
}

// pipe copies src to dst, closing on idle and half-closing dst at EOF.
func pipe(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, 32<<10)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				_ = src.Close()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
					return
				}
			}
			_ = dst.Close()
			_ = src.Close()
			return
		}
	}
}
