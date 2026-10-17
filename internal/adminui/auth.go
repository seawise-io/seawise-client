package adminui

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLen      = 10
	MaxPasswordLen      = 72
	setupLimitWindow    = 10 * time.Minute
	setupMaxFailsPerIP  = 5
	setupMaxFailsGlobal = 50
	loginWindow         = 15 * time.Minute
	loginBaseDelay      = time.Second
	loginMaxDelay       = 10 * time.Second
	loginGlobalWindow   = time.Minute
	loginGlobalMax      = 100
	loginLocalMax       = 30
	maxTrackedIPs       = 1024
	maxConcurrentHash   = 2
	defaultHashWait     = 5 * time.Second
)

var (
	ErrSetupDone    = errors.New("setup already done")
	ErrSetupClosed  = errors.New("setup timed out")
	ErrRateLimited  = errors.New("too many attempts")
	ErrBadPassword  = fmt.Errorf("password must be %d to %d bytes", MinPasswordLen, MaxPasswordLen)
	ErrSetupPending = errors.New("setup required")
	ErrWrongLogin   = errors.New("wrong password")
)

const setupClosedMessage = "Setup timed out for security. Restart the client to set a password."

type AuthConfig struct {
	Store      *store.Store
	Now        func() time.Time
	Logger     *slog.Logger
	BcryptCost int
}

// Auth holds the admin password state, the first-run window and the
// attempt limiters.
type Auth struct {
	cfg AuthConfig
	log *slog.Logger
	// Both clocks must agree the window is open; the wall clock covers suspend.
	deadline     time.Time
	wallDeadline time.Time
	hashWait     time.Duration

	mu         sync.Mutex
	configured bool
	setupFails []time.Time
	setupByIP  map[string][]time.Time
	loginIP    map[string]*ipFails
	loginAll   []time.Time
	loginLocal []time.Time
	dummy      []byte
	hashSlots  chan struct{}
	compare    func(hash, password []byte) error
}

type ipFails struct {
	count int
	last  time.Time
}

// NewAuth keeps a stored password or opens the first-run window.
func NewAuth(cfg AuthConfig) (*Auth, error) {
	if cfg.Store == nil {
		return nil, errors.New("store required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = constants.BcryptCost
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte(randomToken(16)), cfg.BcryptCost)
	if err != nil {
		return nil, err
	}
	start := cfg.Now()
	return &Auth{cfg: cfg, log: cfg.Logger.With("component", "auth"),
		deadline:     start.Add(constants.FirstRunSetupWindow),
		wallDeadline: start.Round(0).Add(constants.FirstRunSetupWindow),
		hashWait:     defaultHashWait,
		configured:   cfg.Store.Secrets().AdminPasswordHash != "",
		loginIP:      map[string]*ipFails{}, setupByIP: map[string][]time.Time{}, dummy: dummy,
		hashSlots: make(chan struct{}, maxConcurrentHash), compare: bcrypt.CompareHashAndPassword}, nil
}

func validPassword(s string) bool { return len(s) >= MinPasswordLen && len(s) <= MaxPasswordLen }

// FirstRunWindowText is the first-run window as shown to people.
func FirstRunWindowText() string {
	m := int(constants.FirstRunSetupWindow / time.Minute)
	if m == 1 {
		return "1 minute"
	}
	return strconv.Itoa(m) + " minutes"
}

func (a *Auth) savePassword(hash []byte) error {
	err := a.cfg.Store.UpdateSecrets(func(s *store.Secrets) error { s.AdminPasswordHash = string(hash); return nil })
	if errors.Is(err, store.ErrNotDurable) {
		a.log.Warn("admin password saved but may not survive a power loss", "error", err)
		return nil
	}
	return err
}

// windowClosed is called with mu held.
func (a *Auth) windowClosed() bool {
	now := a.cfg.Now()
	return !now.Before(a.deadline) || !now.Round(0).Before(a.wallDeadline)
}

// SetupRequired reports that no admin password exists yet.
func (a *Auth) SetupRequired() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.configured
}

// SetupClosed reports that no password exists and the first-run window
// has passed.
func (a *Auth) SetupClosed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.configured && a.windowClosed()
}

// SetupDeadline is when the first-run window closes.
func (a *Auth) SetupDeadline() time.Time { return a.deadline }

func isLoopbackIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Unmap().IsLoopback()
}

// limiterKey groups IPv6 peers by /64, which one host usually controls.
func limiterKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() && !a.IsLoopback() {
		p, _ := a.WithZone("").Prefix(64)
		return p.String()
	}
	return a.String()
}

// Setup sets the first password while the first-run window is open.
// Loopback is outside the global budget so the LAN cannot lock the owner out.
func (a *Auth) Setup(peer, password string) error {
	ip := limiterKey(peer)
	loopback := isLoopbackIP(peer)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.configured {
		return ErrSetupDone
	}
	if a.windowClosed() {
		return ErrSetupClosed
	}
	now := a.cfg.Now()
	a.setupFails = recent(a.setupFails, now, setupLimitWindow)
	mine := recent(a.setupByIP[ip], now, setupLimitWindow)
	if len(mine) == 0 {
		delete(a.setupByIP, ip)
	} else {
		a.setupByIP[ip] = mine
	}
	if len(mine) >= setupMaxFailsPerIP || (!loopback && len(a.setupFails) >= setupMaxFailsGlobal) {
		return ErrRateLimited
	}
	if !validPassword(password) {
		if !loopback {
			a.setupFails = append(a.setupFails, now)
		}
		a.trackSetupFail(ip, mine, now, loopback)
		return ErrBadPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), a.cfg.BcryptCost)
	if err != nil {
		return err
	}
	if a.windowClosed() {
		return ErrSetupClosed
	}
	if err := a.savePassword(hash); err != nil {
		return err
	}
	a.configured = true
	a.setupFails, a.setupByIP = nil, map[string][]time.Time{}
	a.log.Info("admin password set")
	return nil
}

// trackSetupFail is called with mu held; only loopback evicts, so the LAN cannot push the owner out.
func (a *Auth) trackSetupFail(ip string, mine []time.Time, now time.Time, loopback bool) {
	if a.setupByIP[ip] == nil && len(a.setupByIP) >= maxTrackedIPs {
		for k, v := range a.setupByIP {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= setupLimitWindow {
				delete(a.setupByIP, k)
			}
		}
		if len(a.setupByIP) >= maxTrackedIPs {
			if !loopback {
				return
			}
			evictOldestSetup(a.setupByIP)
		}
	}
	a.setupByIP[ip] = append(mine, now)
}

func evictOldestSetup(m map[string][]time.Time) {
	var oldest string
	var t time.Time
	for k, v := range m {
		if len(v) == 0 {
			oldest = k
			break
		}
		if last := v[len(v)-1]; t.IsZero() || last.Before(t) {
			oldest, t = k, last
		}
	}
	delete(m, oldest)
}

// Login checks the password. Attempts are counted before the check so
// parallel guesses from one address cannot all reach it.
func (a *Auth) Login(peer, password string) (time.Duration, error) {
	ip := limiterKey(peer)
	loopback := isLoopbackIP(peer)
	now := a.cfg.Now()
	a.mu.Lock()
	if !a.configured {
		a.mu.Unlock()
		return 0, ErrSetupPending
	}
	// Loopback has its own budget, so LAN failures never use it up.
	budget, limit := &a.loginAll, loginGlobalMax
	if loopback {
		budget, limit = &a.loginLocal, loginLocalMax
	}
	*budget = recent(*budget, now, loginGlobalWindow)
	if len(*budget) >= limit {
		a.mu.Unlock()
		return loginGlobalWindow, ErrRateLimited
	}
	f := a.loginIP[ip]
	if f != nil && now.Sub(f.last) >= loginWindow {
		delete(a.loginIP, ip)
		f = nil
	}
	if f != nil {
		if wait := f.last.Add(loginDelay(f.count)).Sub(now); wait > 0 {
			a.mu.Unlock()
			return wait, ErrRateLimited
		}
	}
	if f == nil {
		if len(a.loginIP) >= maxTrackedIPs {
			for k, v := range a.loginIP {
				if now.Sub(v.last) >= loginWindow {
					delete(a.loginIP, k)
				}
			}
		}
		if len(a.loginIP) >= maxTrackedIPs && loopback {
			evictOldest(a.loginIP)
		}
		if len(a.loginIP) >= maxTrackedIPs {
			a.mu.Unlock()
			return loginBaseDelay, ErrRateLimited
		}
		f = &ipFails{}
		a.loginIP[ip] = f
	}
	f.count++
	f.last = now
	*budget = append(*budget, now)
	a.mu.Unlock()

	// Decrement rather than restore, so concurrent attempts stay counted.
	unreserve := func(success bool) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if cur := a.loginIP[ip]; cur != nil {
			if cur.count > 0 {
				cur.count--
			}
			if success || cur.count == 0 {
				delete(a.loginIP, ip)
			}
		}
		b := *budget
		for i := len(b) - 1; i >= 0; i-- {
			if b[i].Equal(now) {
				*budget = append(b[:i], b[i+1:]...)
				break
			}
		}
	}
	select {
	case a.hashSlots <- struct{}{}:
	case <-time.After(a.hashWait):
		unreserve(false)
		return loginBaseDelay, ErrRateLimited
	}
	hash := a.cfg.Store.Secrets().AdminPasswordHash
	ok := false
	if hash == "" {
		_ = a.compare(a.dummy, []byte(password))
	} else {
		ok = a.compare([]byte(hash), []byte(password)) == nil
	}
	<-a.hashSlots
	if ok {
		unreserve(true)
		return 0, nil
	}
	return loginDelay(f.count), ErrWrongLogin
}

func evictOldest(m map[string]*ipFails) {
	var oldest string
	var t time.Time
	for k, v := range m {
		if t.IsZero() || v.last.Before(t) {
			oldest, t = k, v.last
		}
	}
	delete(m, oldest)
}

func loginDelay(fails int) time.Duration {
	if fails <= 0 {
		return 0
	}
	d := loginBaseDelay << min(fails-1, 8)
	return min(d, loginMaxDelay)
}

func recent(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < window {
			out = append(out, t)
		}
	}
	return out
}

// HTTP handlers.

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"setup_required": s.cfg.Auth.SetupRequired(), "setup_timed_out": s.cfg.Auth.SetupClosed(), "authenticated": false}
	if sess, ok := s.sess.lookup(sessionToken(r)); ok {
		out["authenticated"] = true
		out["csrf"] = sess.csrf
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	switch err := s.cfg.Auth.Setup(peerIP(r.RemoteAddr), body.Password); {
	case err == nil:
	case errors.Is(err, ErrSetupDone):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already set up"})
		return
	case errors.Is(err, ErrSetupClosed):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": setupClosedMessage})
		return
	case errors.Is(err, ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(int(setupLimitWindow/time.Second)))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try later"})
		return
	case errors.Is(err, ErrBadPassword):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	default:
		s.log.Error("setup", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "setup failed"})
		return
	}
	s.sess.removeAll()
	token, csrf := s.sess.create()
	setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil || len(body.Password) > MaxPasswordLen*4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	wait, err := s.cfg.Auth.Login(peerIP(r.RemoteAddr), body.Password)
	switch {
	case err == nil:
	case errors.Is(err, ErrSetupPending):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "setup required"})
		return
	case errors.Is(err, ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int((wait+time.Second-1)/time.Second))))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try later"})
		return
	default:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong password"})
		return
	}
	token, csrf := s.sess.create()
	setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}

func peerIP(remote string) string {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().String()
	}
	return remote
}
