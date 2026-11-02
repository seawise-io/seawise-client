// Package adminui serves the agent's local admin UI: plain HTTP by default,
// HTTPS on the same port with SEAWISE_TLS=auto.
package adminui

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

const (
	MaxAPIBody     = 4 << 10
	maxHeaderBytes = 16 << 10
)

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

//go:embed static/*
var staticFS embed.FS

type Config struct {
	Store        *store.Store
	Auth         *Auth
	Status       func(ctx context.Context) any
	AllowedHosts []string
	// TLS serves the UI over HTTPS only (SEAWISE_TLS=auto); off, it is
	// served over plain HTTP.
	TLS      bool
	Hostname string
	Now      func() time.Time
	Logger   *slog.Logger
	// Resolver and Gateways feed the target review; defaults use the system.
	Resolver         targetpolicy.Resolver
	Gateways         func() []netip.Addr
	OnTargetsChanged func(context.Context)
	// Apps adds and removes local apps; nil turns both off.
	Apps Apps
	// KillSwitch drops or restores all tunnels.
	AccessLog     AccessLog
	KillSwitch    KillSwitchFunc
	PeekTimeout   time.Duration
	MaxConns      int
	MaxConnsPerIP int
}

type Server struct {
	cfg    Config
	log    *slog.Logger
	sess   *sessions
	hosts  map[string]bool
	secure *http.ServeMux
}

func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Auth == nil {
		return nil, errors.New("store and auth required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Resolver == nil {
		cfg.Resolver = defaultResolver
	}
	if cfg.Gateways == nil {
		cfg.Gateways = targetpolicy.Gateways
	}
	if cfg.Status == nil {
		cfg.Status = func(context.Context) any { return struct{}{} }
	}
	s := &Server{cfg: cfg, log: cfg.Logger.With("component", "adminui"), sess: newSessions(cfg.Now), hosts: map[string]bool{}}
	for _, h := range append([]string{cfg.Hostname}, cfg.AllowedHosts...) {
		if h = normalizeHost(h); h != "" {
			s.hosts[h] = true
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /static/{file}", s.handleStatic)
	mux.Handle("GET /api/status", s.requireSession(http.HandlerFunc(s.handleStatus)))
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.Handle("GET /api/targets/review", s.requireSession(http.HandlerFunc(s.handleReviewList)))
	mux.Handle("POST /api/targets/review", s.requireSession(http.HandlerFunc(s.handleReviewAction)))
	mux.Handle("GET /api/apps", s.requireSession(http.HandlerFunc(s.handleAppList)))
	mux.Handle("POST /api/apps/add", s.requireSession(http.HandlerFunc(s.handleAppAdd)))
	mux.Handle("POST /api/apps/delete", s.requireSession(http.HandlerFunc(s.handleAppDelete)))
	mux.Handle("DELETE /api/apps/delete", s.requireSession(http.HandlerFunc(s.handleAppDelete)))
	mux.Handle("GET /api/access-log", s.requireSession(http.HandlerFunc(s.handleAccessLog)))
	mux.Handle("POST /api/kill-switch", s.requireSession(http.HandlerFunc(s.handleKillSwitch)))
	mux.Handle("POST /api/auth/logout", s.requireSession(http.HandlerFunc(s.handleLogout)))
	s.secure = mux
	return s, nil
}

// SecureHandler is served over TLS.
func (s *Server) SecureHandler() http.Handler {
	return s.headers(s.hostCheck(s.scheme(true, s.originCheck(s.limitBody(s.secure)))))
}

// PlainHandler is served over plain HTTP: the UI when TLS is off; with TLS
// on, the loopback health check only.
func (s *Server) PlainHandler() http.Handler {
	if s.cfg.TLS {
		return s.headers(http.HandlerFunc(s.plainTLSOn))
	}
	ui := s.hostCheck(s.scheme(false, s.originCheck(s.limitBody(s.secure))))
	return s.headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopbackHealthz(r) {
			s.handleHealthz(w, r)
			return
		}
		ui.ServeHTTP(w, r)
	}))
}

// Serve runs the servers on ln until ctx is cancelled. cert is required
// with TLS on and unused with it off.
func (s *Server) Serve(ctx context.Context, ln net.Listener, cert *tls.Certificate) error {
	if s.cfg.TLS && cert == nil {
		return errors.New("adminui: TLS needs a certificate")
	}
	tlsL, plainL := splitListener(ln, limits{peek: s.cfg.PeekTimeout, total: s.cfg.MaxConns, perIP: s.cfg.MaxConnsPerIP, plainOnly: !s.cfg.TLS})
	errLog := slog.NewLogLogger(s.log.Handler(), slog.LevelDebug)
	newServer := func(h http.Handler) *http.Server { return newHTTPServer(h, errLog) }
	plain := newServer(s.PlainHandler())
	errs := make(chan error, 2)
	var secure *http.Server
	if s.cfg.TLS {
		secure = newServer(s.SecureHandler())
		secure.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}}
		go func() { errs <- secure.ServeTLS(tlsL, "", "") }()
	}
	go func() { errs <- plain.Serve(plainL) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if secure != nil {
		_ = secure.Shutdown(sctx)
	}
	_ = plain.Shutdown(sctx)
	_ = ln.Close()
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return ctx.Err()
}

func newHTTPServer(h http.Handler, errLog *log.Logger) *http.Server {
	return &http.Server{
		Handler: h, ErrorLog: errLog, MaxHeaderBytes: maxHeaderBytes,
		ReadHeaderTimeout: constants.WebUIReadHeaderTimeout, ReadTimeout: constants.WebUIReadTimeout,
		WriteTimeout: constants.WebUIWriteTimeout, IdleTimeout: constants.WebUIIdleTimeout,
	}
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, s.hosts) {
			http.Error(w, "host not allowed", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originCheck refuses cross-site unsafe requests before any handler runs.
func (s *Server) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) && !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxAPIBody)
		next.ServeHTTP(w, r)
	})
}

func safeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// sameOrigin compares the Origin with this server's scheme and host.
func sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		sch := "http://"
		if isHTTPS(r) {
			sch = "https://"
		}
		return strings.EqualFold(o, sch+r.Host)
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

type ctxKey struct{}

// requireSession needs a session cookie, plus X-CSRF-Token on unsafe methods.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.sess.lookup(sessionToken(r))
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		if !safeMethod(r.Method) && !equalSecret(r.Header.Get("X-CSRF-Token"), sess.csrf) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or wrong CSRF token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

type httpsKey struct{}

// scheme records whether the request arrived over TLS, for the origin check
// and the session cookie.
func (s *Server) scheme(https bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, withHTTPS(r, https))
	})
}

func withHTTPS(r *http.Request, on bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), httpsKey{}, on))
}

func isHTTPS(r *http.Request) bool {
	on, _ := r.Context().Value(httpsKey{}).(bool)
	return on
}

func loopbackHealthz(r *http.Request) bool {
	return r.URL.Path == "/healthz" && r.Method == http.MethodGet && loopbackPeer(r.RemoteAddr)
}

// plainTLSOn answers plain HTTP while the UI is HTTPS only.
func (s *Server) plainTLSOn(w http.ResponseWriter, r *http.Request) {
	if loopbackHealthz(r) {
		s.handleHealthz(w, r)
		return
	}
	if !hostAllowed(r.Host, s.hosts) {
		http.Error(w, "host not allowed", http.StatusMisdirectedRequest)
		return
	}
	http.Error(w, "Client sent an HTTP request to an HTTPS server.", http.StatusBadRequest)
}

func loopbackPeer(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	return err == nil && ap.Addr().Unmap().IsLoopback()
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.serveFile(w, "index.html", "text/html; charset=utf-8")
}

// handleStatic maps known names to assets so the request path never reaches a file name.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("file") {
	case "app.js":
		s.serveFile(w, "app.js", "text/javascript; charset=utf-8")
	case "app.css":
		s.serveFile(w, "app.css", "text/css; charset=utf-8")
	default:
		http.NotFound(w, r)
	}
}

// serveFile writes an embedded asset; callers pass constant names.
func (s *Server) serveFile(w http.ResponseWriter, name, ct string) {
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(b)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Status(r.Context()))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sess.remove(sessionToken(r))
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeBody reads one JSON object with known fields only.
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
