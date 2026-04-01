package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/seawise/client/internal/auth"
	"github.com/seawise/client/internal/constants"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName    = "seawise_session"
	sessionMaxAge        = 8 * time.Hour // 8 hours
	sessionCleanupPeriod = 15 * time.Minute

	// Rate limiting constants
	rateLimitWindow    = 15 * time.Minute // Reset window
	rateLimitMaxFails  = 5                // Max failures before lockout
	rateLimitBaseDelay = 500 * time.Millisecond
	rateLimitMaxDelay  = 30 * time.Second
)

// rateLimitEntry tracks failed login attempts per IP
type rateLimitEntry struct {
	failures    int
	lastFail    time.Time
	lockedUntil time.Time
}

// authManager handles local password authentication for the web UI.
type authManager struct {
	mu           sync.RWMutex
	passwordHash []byte               // bcrypt hash loaded from disk
	sessions     map[string]time.Time // token -> expiry
	passwordFile string
	rateLimits   map[string]*rateLimitEntry // IP -> rate limit state
	stopChan     chan struct{}              // Signal cleanup goroutine to exit
	stopOnce     sync.Once                  // Prevents double-close panic on stopChan
}

func newAuthManager() *authManager {
	pwFile := auth.PasswordFile()

	am := &authManager{
		sessions:     make(map[string]time.Time),
		passwordFile: pwFile,
		rateLimits:   make(map[string]*rateLimitEntry),
		stopChan:     make(chan struct{}),
	}

	if data, err := os.ReadFile(pwFile); err == nil && len(data) > 0 { // #nosec G304
		am.passwordHash = data
		slog.Info("Password protection enabled", "component", "auth")
	} else {
		slog.Info("No password set — password will be required on first web UI visit", "component", "auth")
	}

	am.startCleanup()

	return am
}

func (am *authManager) hasPassword() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.passwordHash) > 0
}

func (am *authManager) setPassword(password string) error {
	hash, err := auth.HashAndSavePassword(password)
	if err != nil {
		return err
	}

	am.mu.Lock()
	am.passwordHash = hash
	am.mu.Unlock()

	slog.Info("Password set/updated", "component", "auth")
	return nil
}

func (am *authManager) checkPassword(password string) bool {
	am.mu.RLock()
	hash := am.passwordHash
	am.mu.RUnlock()

	if len(hash) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func (am *authManager) createSession() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	am.mu.Lock()
	am.sessions[token] = time.Now().Add(sessionMaxAge)
	am.mu.Unlock()

	return token, nil
}

func (am *authManager) validateSession(token string) bool {
	if token == "" {
		return false
	}

	am.mu.RLock()
	expiry, exists := am.sessions[token]
	am.mu.RUnlock()

	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		am.mu.Lock()
		delete(am.sessions, token)
		am.mu.Unlock()
		return false
	}
	return true
}

func (am *authManager) deleteSession(token string) {
	am.mu.Lock()
	delete(am.sessions, token)
	am.mu.Unlock()
}

func (am *authManager) invalidateAllSessions() {
	am.mu.Lock()
	am.sessions = make(map[string]time.Time)
	am.mu.Unlock()
}

// startCleanup periodically removes expired sessions.
func (am *authManager) startCleanup() {
	go func() {
		ticker := time.NewTicker(sessionCleanupPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-am.stopChan:
				return
			case <-ticker.C:
				am.cleanupExpiredSessions()
			}
		}
	}()
}

// Stop signals the cleanup goroutine to exit. Safe to call multiple times.
func (am *authManager) Stop() {
	am.stopOnce.Do(func() {
		close(am.stopChan)
	})
}

// cleanupExpiredSessions removes expired sessions and stale rate limit entries.
func (am *authManager) cleanupExpiredSessions() {
	now := time.Now()
	am.mu.Lock()
	defer am.mu.Unlock()

	expired := 0
	for token, expiry := range am.sessions {
		if now.After(expiry) {
			delete(am.sessions, token)
			expired++
		}
	}
	if expired > 0 {
		slog.Info("Cleaned up expired sessions", "component", "auth", "count", expired)
	}

	for ip, entry := range am.rateLimits {
		if now.Sub(entry.lastFail) > rateLimitWindow {
			delete(am.rateLimits, ip)
		}
	}
}

// checkRateLimit returns true if the IP is allowed to attempt login.
func (am *authManager) checkRateLimit(ip string) (allowed bool, retryAfter time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()

	entry, exists := am.rateLimits[ip]
	if !exists {
		return true, 0
	}

	now := time.Now()

	if now.Before(entry.lockedUntil) {
		return false, entry.lockedUntil.Sub(now)
	}

	if now.Sub(entry.lastFail) > rateLimitWindow {
		delete(am.rateLimits, ip)
		return true, 0
	}

	return true, 0
}

// recordFailedLogin records a failed login attempt and returns the lockout delay.
func (am *authManager) recordFailedLogin(ip string) time.Duration {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	entry, exists := am.rateLimits[ip]

	if !exists || now.Sub(entry.lastFail) > rateLimitWindow {
		entry = &rateLimitEntry{failures: 0}
		am.rateLimits[ip] = entry
	}

	entry.failures++
	entry.lastFail = now

	shift := entry.failures - 1
	if shift > 30 {
		shift = 30
	}
	delay := rateLimitBaseDelay * time.Duration(1<<uint(shift))
	if delay > rateLimitMaxDelay {
		delay = rateLimitMaxDelay
	}

	if entry.failures >= rateLimitMaxFails {
		entry.lockedUntil = now.Add(rateLimitWindow)
		slog.Warn("IP locked out after failed attempts", "component", "auth", "ip", ip, "lockout_duration", rateLimitWindow, "attempts", entry.failures)
	} else if delay > 0 {
		entry.lockedUntil = now.Add(delay)
	}

	return delay
}

// clearRateLimit clears rate limit for an IP after successful login.
func (am *authManager) clearRateLimit(ip string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.rateLimits, ip)
}

// middleware wraps handlers with CSRF and authentication checks.
func (am *authManager) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// CSRF protection for state-changing requests
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			if origin != "" {
				validOrigins := []string{
					"http://localhost",
					"http://127.0.0.1",
					"http://[::1]",
					"https://localhost",
					"https://127.0.0.1",
					"https://[::1]",
				}
				// Allow the request's own host as valid origin (Docker port mapping,
				// LAN access). The Host header is what the browser used to reach us.
				if host := r.Host; host != "" {
					validOrigins = append(validOrigins, "http://"+host, "https://"+host)
					// Also allow without port for standard ports
					if h, _, err := net.SplitHostPort(host); err == nil {
						validOrigins = append(validOrigins, "http://"+h, "https://"+h)
					}
				}
				isValidOrigin := false
				for _, valid := range validOrigins {
					if origin == valid || len(origin) > len(valid) && origin[:len(valid)+1] == valid+":" {
						isValidOrigin = true
						break
					}
				}
				if !isValidOrigin {
					slog.Warn("Blocked request from invalid origin", "component", "csrf", "origin", origin, "path", path)
					writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "Cross-origin requests not allowed"})
					return
				}
			} else if referer != "" {
				// Check delimiter after host to prevent subdomain bypass
				isValidReferer := false
				validPrefixes := []string{
					"http://localhost",
					"http://127.0.0.1",
					"http://[::1]",
					"https://localhost",
					"https://127.0.0.1",
					"https://[::1]",
				}
				// Allow the request's own host as valid referer
				if host := r.Host; host != "" {
					validPrefixes = append(validPrefixes, "http://"+host, "https://"+host)
				}
				for _, prefix := range validPrefixes {
					if strings.HasPrefix(referer, prefix) {
						remainder := referer[len(prefix):]
						if remainder == "" || remainder[0] == ':' || remainder[0] == '/' {
							isValidReferer = true
							break
						}
					}
				}
				if !isValidReferer {
					slog.Warn("Blocked request with invalid referer", "component", "csrf", "referer", referer, "path", path)
					writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "Cross-origin requests not allowed"})
					return
				}
			} else {
				slog.Warn("Blocked request with no origin/referer", "component", "csrf", "path", path)
				writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "Origin or Referer header required"})
				return
			}
		}

		// Auth endpoints and status are always accessible (needed for setup + login UI)
		if path == "/api/auth/status" || path == "/api/auth/login" || path == "/api/auth/set-password" || path == "/api/status" {
			next.ServeHTTP(w, r)
			return
		}

		// No password set — require setup before allowing any other action.
		// Only the home page (UI), static assets, and auth/status endpoints pass through.
		if !am.hasPassword() {
			if path == "/" || strings.HasPrefix(path, "/static/") {
				next.ServeHTTP(w, r)
				return
			}
			writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "Password setup required"})
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !am.validateSession(cookie.Value) {
			if len(path) > 4 && path[:5] == "/api/" {
				writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// setSessionCookie sets the session cookie on the response.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie removes the session cookie.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := false
	if s.auth.hasPassword() {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil {
			authenticated = s.auth.validateSession(cookie.Value)
		}
	}

	writeJSON(w, map[string]interface{}{
		"password_set":  s.auth.hasPassword(),
		"authenticated": authenticated,
	})
}

func (s *Server) handleAuthSetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.auth.hasPassword() {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !s.auth.validateSession(cookie.Value) {
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxAuthBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Request too large"})
		return
	}

	var req struct {
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	if len(req.Password) < 8 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Password must be at least 8 characters"})
		return
	}

	if s.auth.hasPassword() && !s.auth.checkPassword(req.CurrentPassword) {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "Current password is incorrect"})
		return
	}

	if err := s.auth.setPassword(req.Password); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "Failed to set password"})
		return
	}

	s.auth.invalidateAllSessions()
	token, err := s.auth.createSession()
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create session"})
		return
	}
	setSessionCookie(w, r, token)

	writeJSON(w, map[string]interface{}{"success": true})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Strip port from RemoteAddr for consistent rate limit bucketing
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	if os.Getenv("SEAWISE_TRUST_PROXY") == "true" {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			candidate := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			// Validate it's actually an IP
			if net.ParseIP(candidate) != nil {
				clientIP = candidate
			}
		}
	}

	allowed, retryAfter := s.auth.checkRateLimit(clientIP)
	if !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(retryAfter.Seconds())),
		})
		return
	}

	if !s.auth.hasPassword() {
		writeJSON(w, map[string]interface{}{"success": true})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxAuthBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Request too large"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "Invalid request"})
		return
	}

	if !s.auth.checkPassword(req.Password) {
		delay := s.auth.recordFailedLogin(clientIP)
		if delay > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(delay.Seconds())+1))
			writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{
				"error": fmt.Sprintf("Incorrect password. Try again in %d seconds.", int(delay.Seconds())+1),
			})
		} else {
			writeJSONStatus(w, http.StatusUnauthorized, map[string]string{"error": "Incorrect password"})
		}
		return
	}

	s.auth.clearRateLimit(clientIP)

	token, err := s.auth.createSession()
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create session"})
		return
	}
	setSessionCookie(w, r, token)

	writeJSON(w, map[string]interface{}{"success": true})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.auth.deleteSession(cookie.Value)
	}
	clearSessionCookie(w)

	writeJSON(w, map[string]interface{}{"success": true})
}

// Password removal intentionally removed — password is mandatory (set on first run).
