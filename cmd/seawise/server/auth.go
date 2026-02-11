package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	failures int
	lastFail time.Time
	lockedUntil time.Time
}

// authManager handles local password authentication for the web UI.
type authManager struct {
	mu           sync.RWMutex
	passwordHash []byte               // bcrypt hash loaded from disk
	sessions     map[string]time.Time // token -> expiry
	passwordFile string
	setupToken   string // One-time token for initial password setup
	rateLimits   map[string]*rateLimitEntry // IP -> rate limit state
	stopChan     chan struct{} // Signal cleanup goroutine to exit
	stopOnce     sync.Once    // Prevents double-close panic on stopChan
}

func newAuthManager() *authManager {
	// Use shared password file path from auth package
	pwFile := auth.PasswordFile()

	am := &authManager{
		sessions:     make(map[string]time.Time),
		passwordFile: pwFile,
		rateLimits:   make(map[string]*rateLimitEntry),
		stopChan:     make(chan struct{}),
	}

	// Load existing password hash
	if data, err := os.ReadFile(pwFile); err == nil && len(data) > 0 {
		am.passwordHash = data
		log.Printf("[Auth] Password protection enabled")
	} else {
		// Generate a one-time setup token for initial password creation
		// SECURITY: This prevents unauthorized password setting by attackers
		tokenBytes := make([]byte, 16)
		if _, err := rand.Read(tokenBytes); err == nil {
			am.setupToken = hex.EncodeToString(tokenBytes)
			// SECURITY: Write token to file instead of logging (prevents exposure in centralized logs)
			tokenFile := auth.SetupTokenFile()
			if writeErr := os.WriteFile(tokenFile, []byte(am.setupToken), 0600); writeErr == nil {
				log.Printf("[Auth] No password set — setup token written to: %s", tokenFile)
				log.Printf("[Auth] Use this token at http://localhost:8082 to set your password")
			} else {
				// Fallback: print to console only if file write fails (local only, not logged)
				log.Printf("[Auth] No password set — setup token (DO NOT SHARE): %s", am.setupToken)
			}
		} else {
			log.Printf("[Auth] Failed to generate setup token: %v", err)
		}
	}

	// Start background cleanup of expired sessions
	am.startCleanup()

	return am
}

// hasPassword returns true if a password has been configured.
func (am *authManager) hasPassword() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.passwordHash) > 0
}

// setPassword hashes and stores a new password.
func (am *authManager) setPassword(password string) error {
	hash, err := auth.HashAndSavePassword(password)
	if err != nil {
		return err
	}

	am.mu.Lock()
	am.passwordHash = hash
	am.mu.Unlock()

	log.Printf("[Auth] Password set/updated")
	return nil
}

// checkPassword verifies a password against the stored hash.
func (am *authManager) checkPassword(password string) bool {
	am.mu.RLock()
	hash := am.passwordHash
	am.mu.RUnlock()

	if len(hash) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// createSession generates a new session token and stores it.
func (am *authManager) createSession() string {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Printf("[Auth] Failed to generate session token: %v", err)
		return ""
	}
	token := hex.EncodeToString(tokenBytes)

	am.mu.Lock()
	am.sessions[token] = time.Now().Add(sessionMaxAge)
	am.mu.Unlock()

	return token
}

// validateSession checks if a session token is valid.
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

// deleteSession removes a session.
func (am *authManager) deleteSession(token string) {
	am.mu.Lock()
	delete(am.sessions, token)
	am.mu.Unlock()
}

// invalidateAllSessions clears all sessions (used on password change).
func (am *authManager) invalidateAllSessions() {
	am.mu.Lock()
	am.sessions = make(map[string]time.Time)
	am.mu.Unlock()
}

// startCleanup periodically removes expired sessions to prevent memory leaks.
// The goroutine exits when Stop() is called.
func (am *authManager) startCleanup() {
	go func() {
		ticker := time.NewTicker(sessionCleanupPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-am.stopChan:
				return // Exit goroutine when stop signal received
			case <-ticker.C:
				am.cleanupExpiredSessions()
			}
		}
	}()
}

// Stop signals the cleanup goroutine to exit. Call on server shutdown.
// Safe to call multiple times — uses sync.Once to prevent double-close panic.
func (am *authManager) Stop() {
	am.stopOnce.Do(func() {
		close(am.stopChan)
	})
}

// cleanupExpiredSessions removes all expired sessions from memory.
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
		log.Printf("[Auth] Cleaned up %d expired sessions", expired)
	}

	// Also clean up old rate limit entries
	for ip, entry := range am.rateLimits {
		if now.Sub(entry.lastFail) > rateLimitWindow {
			delete(am.rateLimits, ip)
		}
	}
}

// checkRateLimit returns true if the IP is allowed to attempt login, false if blocked
func (am *authManager) checkRateLimit(ip string) (allowed bool, retryAfter time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()

	entry, exists := am.rateLimits[ip]
	if !exists {
		return true, 0
	}

	now := time.Now()

	// Check if locked out
	if now.Before(entry.lockedUntil) {
		return false, entry.lockedUntil.Sub(now)
	}

	// Reset if window expired
	if now.Sub(entry.lastFail) > rateLimitWindow {
		delete(am.rateLimits, ip)
		return true, 0
	}

	return true, 0
}

// recordFailedLogin records a failed login attempt and returns the delay to apply
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

	// Calculate exponential backoff delay
	delay := rateLimitBaseDelay * time.Duration(1<<uint(entry.failures-1))
	if delay > rateLimitMaxDelay {
		delay = rateLimitMaxDelay
	}

	// Lock out for the delay period (enforced by checkRateLimit on next request)
	if entry.failures >= rateLimitMaxFails {
		entry.lockedUntil = now.Add(rateLimitWindow)
		log.Printf("[Auth] IP %s locked out for %v after %d failed attempts", ip, rateLimitWindow, entry.failures)
	} else if delay > 0 {
		entry.lockedUntil = now.Add(delay)
	}

	return delay
}

// clearRateLimit clears rate limit for an IP after successful login
func (am *authManager) clearRateLimit(ip string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.rateLimits, ip)
}

// removePassword deletes the stored password and clears all sessions.
func (am *authManager) removePassword() error {
	am.mu.Lock()
	am.passwordHash = nil
	am.sessions = make(map[string]time.Time)
	am.mu.Unlock()

	if err := os.Remove(am.passwordFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	log.Printf("[Auth] Password removed — web UI is unprotected")
	return nil
}

// middleware returns an http.Handler that checks authentication and CSRF protection.
// Unauthenticated requests to protected paths get a 401.
func (am *authManager) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// CSRF protection for state-changing requests (POST, DELETE, PUT, PATCH)
		// This protects against malicious websites triggering actions via JavaScript
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			// Allow requests with no Origin (same-origin requests from older browsers)
			// or requests where Origin matches localhost
			if origin != "" {
				// Check if origin is localhost (various forms)
				validOrigins := []string{
					"http://localhost",
					"http://127.0.0.1",
					"https://localhost",
					"https://127.0.0.1",
				}
				isValidOrigin := false
				for _, valid := range validOrigins {
					// Origin header includes scheme but not port, so we check prefix
					if origin == valid || len(origin) > len(valid) && origin[:len(valid)+1] == valid+":" {
						isValidOrigin = true
						break
					}
				}
				if !isValidOrigin {
					log.Printf("[CSRF] Blocked request from origin: %s to %s", origin, path)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{"error": "Cross-origin requests not allowed"})
					return
				}
			} else if referer != "" {
				// Fall back to Referer check if no Origin header
				// SECURITY: Must check for delimiter after host to prevent localhost.attacker.com bypass
				isValidReferer := false
				validPrefixes := []string{
					"http://localhost",
					"http://127.0.0.1",
					"https://localhost",
					"https://127.0.0.1",
				}
				for _, prefix := range validPrefixes {
					if strings.HasPrefix(referer, prefix) {
						// Must be followed by end, port (:), or path (/)
						remainder := referer[len(prefix):]
						if remainder == "" || remainder[0] == ':' || remainder[0] == '/' {
							isValidReferer = true
							break
						}
					}
				}
				if !isValidReferer {
					log.Printf("[CSRF] Blocked request with referer: %s to %s", referer, path)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]string{"error": "Cross-origin requests not allowed"})
					return
				}
			} else {
				// SECURITY: Block requests with no Origin AND no Referer
				// This prevents CSRF via curl/wget-style attacks
				log.Printf("[CSRF] Blocked request with no origin/referer to %s", path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Origin or Referer header required"})
				return
			}
		}

		// Auth endpoints are always accessible (after CSRF check)
		if path == "/api/auth/status" || path == "/api/auth/login" || path == "/api/auth/set-password" {
			next.ServeHTTP(w, r)
			return
		}

		// If no password is set, allow everything (CSRF already validated above)
		if !am.hasPassword() {
			next.ServeHTTP(w, r)
			return
		}

		// Check session cookie
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !am.validateSession(cookie.Value) {
			// For API calls, return 401 JSON
			if len(path) > 4 && path[:5] == "/api/" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
				return
			}
			// For page requests, serve the page (JS will handle showing login)
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// setSessionCookie sets the session cookie on the response.
func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
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

// --- HTTP Handlers ---

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	authenticated := false
	if s.auth.hasPassword() {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil {
			authenticated = s.auth.validateSession(cookie.Value)
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"password_set":  s.auth.hasPassword(),
		"authenticated": authenticated,
	})
}

func (s *Server) handleAuthSetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// If password already set, require current password
	if s.auth.hasPassword() {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !s.auth.validateSession(cookie.Value) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxAuthBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Request too large"})
		return
	}

	var req struct {
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
		SetupToken      string `json:"setup_token"` // Required for initial setup
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	if len(req.Password) < 8 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Password must be at least 8 characters"})
		return
	}

	// SECURITY: If setting initial password, require setup token from console
	if !s.auth.hasPassword() {
		s.auth.mu.RLock()
		validToken := s.auth.setupToken != "" && subtle.ConstantTimeCompare([]byte(req.SetupToken), []byte(s.auth.setupToken)) == 1
		s.auth.mu.RUnlock()

		if !validToken {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid setup token. Check console for the token."})
			return
		}
	}

	// If changing password, verify current
	if s.auth.hasPassword() && !s.auth.checkPassword(req.CurrentPassword) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Current password is incorrect"})
		return
	}

	if err := s.auth.setPassword(req.Password); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to set password"})
		return
	}

	// Clear setup token after successful password set
	s.auth.mu.Lock()
	s.auth.setupToken = ""
	s.auth.mu.Unlock()

	// Clear CLI session (force re-auth with new password)
	if err := auth.ClearCLISession(); err != nil {
		log.Printf("[auth] Warning: failed to clear CLI session: %v", err)
	}

	// Invalidate old sessions, create new one
	s.auth.invalidateAllSessions()
	token := s.auth.createSession()
	setSessionCookie(w, token)

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Get client IP for rate limiting
	// SECURITY: Only trust X-Forwarded-For if explicitly behind a trusted proxy
	// Without this check, attackers can spoof their IP to bypass rate limiting
	clientIP := r.RemoteAddr
	if os.Getenv("SEAWISE_TRUST_PROXY") == "true" {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			// Take first IP (original client) from the chain
			clientIP = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
	}

	// SECURITY: Check rate limit before processing
	allowed, retryAfter := s.auth.checkRateLimit(clientIP)
	if !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(retryAfter.Seconds())),
		})
		return
	}

	if !s.auth.hasPassword() {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxAuthBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Request too large"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	if !s.auth.checkPassword(req.Password) {
		// Record failed attempt — sets lockout duration for next request
		delay := s.auth.recordFailedLogin(clientIP)
		if delay > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(delay.Seconds())+1))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("Incorrect password. Try again in %d seconds.", int(delay.Seconds())+1),
			})
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect password"})
		}
		return
	}

	// Successful login - clear rate limit
	s.auth.clearRateLimit(clientIP)

	token := s.auth.createSession()
	setSessionCookie(w, token)

	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *Server) handleAuthRemovePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Must be authenticated to remove password
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || !s.auth.validateSession(cookie.Value) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxAuthBodySize)
	body, _ := io.ReadAll(r.Body)

	var req struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil || !s.auth.checkPassword(req.Password) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect password"})
		return
	}

	if err := s.auth.removePassword(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to remove password"})
		return
	}

	// Clear CLI session too
	if err := auth.ClearCLISession(); err != nil {
		log.Printf("[auth] Warning: failed to clear CLI session: %v", err)
	}

	clearSessionCookie(w)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}
