package adminui

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	SetupCodeFile       = "setup-code"
	MinPasswordLen      = 10
	MaxPasswordLen      = 72
	maxPasswordFile     = 1 << 10
	setupWindow         = 10 * time.Minute
	setupMaxFailsPerIP  = 5
	setupMaxFailsGlobal = 50
	setupRotateAfter    = 100
	loginWindow         = 15 * time.Minute
	loginBaseDelay      = time.Second
	loginMaxDelay       = 10 * time.Second
	loginGlobalWindow   = time.Minute
	loginGlobalMax      = 100
	maxTrackedIPs       = 1024
	maxConcurrentHash   = 2
	hashWait            = 5 * time.Second
)

var (
	ErrSetupDone    = errors.New("setup already done")
	ErrSetupCode    = errors.New("wrong setup code")
	ErrRateLimited  = errors.New("too many attempts")
	ErrBadPassword  = fmt.Errorf("password must be %d to %d bytes", MinPasswordLen, MaxPasswordLen)
	ErrSetupPending = errors.New("setup required")
	ErrWrongLogin   = errors.New("wrong password")
)

type AuthConfig struct {
	Store *store.Store
	// PasswordFile is SEAWISE_ADMIN_PASSWORD_FILE.
	PasswordFile string
	Now          func() time.Time
	Logger       *slog.Logger
	BcryptCost   int
}

// Auth holds the admin password state, the one-time setup code and the
// attempt limiters.
type Auth struct {
	cfg  AuthConfig
	log  *slog.Logger
	path string

	mu         sync.Mutex
	code       string
	setupFails []time.Time
	setupByIP  map[string][]time.Time
	setupTotal int
	loginIP    map[string]*ipFails
	loginAll   []time.Time
	dummy      []byte
	hashSlots  chan struct{}
	compare    func(hash, password []byte) error
}

type ipFails struct {
	count int
	last  time.Time
}

// NewAuth applies SEAWISE_ADMIN_PASSWORD_FILE, or keeps a stored password,
// or enters setup mode with a new one-time code written to v2/setup-code.
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
	a := &Auth{cfg: cfg, log: cfg.Logger.With("component", "auth"), path: filepath.Join(cfg.Store.Dir(), SetupCodeFile),
		loginIP: map[string]*ipFails{}, setupByIP: map[string][]time.Time{}, dummy: dummy,
		hashSlots: make(chan struct{}, maxConcurrentHash), compare: bcrypt.CompareHashAndPassword}

	if cfg.PasswordFile != "" {
		pw, err := readPasswordFile(cfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("admin password file: %w", err)
		}
		hash := cfg.Store.Secrets().AdminPasswordHash
		if hash == "" || bcrypt.CompareHashAndPassword([]byte(hash), pw) != nil {
			if err := a.storePassword(pw); err != nil {
				return nil, err
			}
			a.log.Info("admin password set from file")
		}
		return a, a.removeCodeFile()
	}
	if cfg.Store.Secrets().AdminPasswordHash != "" {
		return a, a.removeCodeFile()
	}
	if err := a.newCode(); err != nil {
		return nil, err
	}
	return a, nil
}

func readPasswordFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPasswordFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPasswordFile {
		return nil, errors.New("file too large")
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if !validPassword(s) {
		return nil, ErrBadPassword
	}
	return []byte(s), nil
}

func validPassword(s string) bool { return len(s) >= MinPasswordLen && len(s) <= MaxPasswordLen }

func (a *Auth) storePassword(pw []byte) error {
	hash, err := bcrypt.GenerateFromPassword(pw, a.cfg.BcryptCost)
	if err != nil {
		return err
	}
	err = a.cfg.Store.UpdateSecrets(func(s *store.Secrets) error { s.AdminPasswordHash = string(hash); return nil })
	if err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	return nil
}

// newCode makes a 100-bit code and writes it, 0600, for the operator.
// Caller holds mu or is the constructor.
func (a *Auth) newCode() error {
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:20]
	if err := store.WriteFileAtomic(a.path, []byte(displayCode(code)+"\n"), 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	a.code = code
	a.setupFails, a.setupTotal = nil, 0
	a.setupByIP = map[string][]time.Time{}
	return nil
}

func (a *Auth) removeCodeFile() error {
	if err := os.Remove(a.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func displayCode(c string) string {
	var parts []string
	for i := 0; i < len(c); i += 4 {
		parts = append(parts, c[i:min(i+4, len(c))])
	}
	return strings.Join(parts, "-")
}

func normalizeCode(s string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.ToUpper(strings.TrimSpace(s)))
}

// currentCode returns the code in display form, or "" once configured. The
// code is only ever shown through the 0600 file, never logged.
func (a *Auth) currentCode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.code == "" {
		return ""
	}
	return displayCode(a.code)
}

func (a *Auth) SetupRequired() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.code != ""
}

// CodePath is where the setup code is written.
func (a *Auth) CodePath() string { return a.path }

func isLoopbackIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Unmap().IsLoopback()
}

// Setup sets the first password. Failures are limited per address and by a
// larger global budget that does not apply to loopback, so a LAN peer
// cannot lock the owner out of setting up on the machine itself.
func (a *Auth) Setup(ip, code, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.code == "" {
		return ErrSetupDone
	}
	now := a.cfg.Now()
	a.setupFails = recent(a.setupFails, now, setupWindow)
	mine := recent(a.setupByIP[ip], now, setupWindow)
	if len(mine) == 0 {
		delete(a.setupByIP, ip)
	} else {
		a.setupByIP[ip] = mine
	}
	if len(mine) >= setupMaxFailsPerIP || (!isLoopbackIP(ip) && len(a.setupFails) >= setupMaxFailsGlobal) {
		return ErrRateLimited
	}
	if !equalSecret(normalizeCode(code), a.code) {
		a.setupFails = append(a.setupFails, now)
		if len(a.setupByIP) < maxTrackedIPs || a.setupByIP[ip] != nil {
			a.setupByIP[ip] = append(mine, now)
		}
		a.setupTotal++
		if a.setupTotal >= setupRotateAfter {
			if err := a.newCode(); err != nil {
				return err
			}
			a.log.Warn("too many wrong setup codes; a new setup code was written", "file", a.path)
		}
		return ErrSetupCode
	}
	if !validPassword(password) {
		return ErrBadPassword
	}
	if err := a.storePassword([]byte(password)); err != nil {
		return err
	}
	a.code = ""
	if err := a.removeCodeFile(); err != nil {
		a.log.Warn("remove setup code file", "error", err)
	}
	a.log.Info("admin password set")
	return nil
}

// Login checks the password. The attempt is counted before the password
// check runs, so parallel guesses from one address cannot all reach it;
// password checks run at most maxConcurrentHash at a time. The global
// budget does not apply to loopback.
func (a *Auth) Login(ip, password string) (time.Duration, error) {
	now := a.cfg.Now()
	a.mu.Lock()
	if a.code != "" {
		a.mu.Unlock()
		return 0, ErrSetupPending
	}
	a.loginAll = recent(a.loginAll, now, loginGlobalWindow)
	if !isLoopbackIP(ip) && len(a.loginAll) >= loginGlobalMax {
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
		if len(a.loginIP) >= maxTrackedIPs {
			a.mu.Unlock()
			return loginBaseDelay, ErrRateLimited
		}
		f = &ipFails{}
		a.loginIP[ip] = f
	}
	prev := *f
	f.count++
	f.last = now
	a.loginAll = append(a.loginAll, now)
	a.mu.Unlock()

	// unreserve gives the attempt back; success also clears the address.
	unreserve := func(success bool) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if cur := a.loginIP[ip]; cur != nil {
			if success || prev.count == 0 {
				delete(a.loginIP, ip)
			} else {
				*cur = prev
			}
		}
		for i := len(a.loginAll) - 1; i >= 0; i-- {
			if a.loginAll[i].Equal(now) {
				a.loginAll = append(a.loginAll[:i], a.loginAll[i+1:]...)
				break
			}
		}
	}
	select {
	case a.hashSlots <- struct{}{}:
	case <-time.After(hashWait):
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
	out := map[string]any{"setup_required": s.cfg.Auth.SetupRequired(), "authenticated": false}
	if sess, ok := s.sess.lookup(sessionToken(r)); ok {
		out["authenticated"] = true
		out["csrf"] = sess.csrf
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	switch err := s.cfg.Auth.Setup(peerIP(r.RemoteAddr), body.Code, body.Password); {
	case err == nil:
	case errors.Is(err, ErrSetupDone):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "already set up"})
		return
	case errors.Is(err, ErrRateLimited):
		w.Header().Set("Retry-After", strconv.Itoa(int(setupWindow/time.Second)))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try later"})
		return
	case errors.Is(err, ErrSetupCode):
		s.log.Warn("wrong setup code", "remote", peerIP(r.RemoteAddr))
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "wrong setup code"})
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
