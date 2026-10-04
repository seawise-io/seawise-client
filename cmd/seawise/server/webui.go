package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/pem"
	"fmt"
	"html/template"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/paths"
)

//go:embed templates/*
var templates embed.FS

var indexTemplate = template.Must(template.ParseFS(templates, "templates/index.html"))

func firstRunHintURL(bindAddr string, port int) string {
	scheme := "http"
	if os.Getenv("SEAWISE_TLS") == "auto" {
		scheme = "https"
	}
	host := bindAddr
	switch host {
	case "0.0.0.0", "":
		host = "127.0.0.1"
	case "::", "[::]":
		host = "[::1]"
	default:
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			host = "[" + host + "]"
		}
	}
	return scheme + "://" + host + ":" + strconv.Itoa(port) + "/"
}

func isLoopbackBindAddr(bindAddr string) bool {
	switch bindAddr {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(bindAddr); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (s *Server) startWebUI(ctx context.Context, port int) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/auth/set-password", s.handleAuthSetPassword)

	mux.HandleFunc("/static/", handleStatic)
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/api/pair/start", s.handlePairStart)
	mux.HandleFunc("/api/pair/poll", s.handlePairPoll)
	mux.HandleFunc("/api/pair/cancel", s.handlePairCancel)
	mux.HandleFunc("/api/services/add", s.handleAddService)
	mux.HandleFunc("/api/services/list", s.handleListServices)
	mux.HandleFunc("/api/services/delete", s.handleDeleteService)
	mux.HandleFunc("/api/unpair", s.handleUnpair)

	bindAddr := os.Getenv("SEAWISE_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	if !s.auth.hasPassword() && !isLoopbackBindAddr(bindAddr) {
		slog.Warn(
			"First-run wizard active on a non-loopback address, set a password immediately",
			"component", "webui",
			"bind_addr", bindAddr,
			"hint", "Open "+firstRunHintURL(bindAddr, port)+" and enter the setup code logged above to set a password.",
		)
	}

	handler := s.auth.middleware(mux)

	srv := &http.Server{
		Addr:              bindAddr + ":" + strconv.Itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: constants.WebUIReadHeaderTimeout,
		ReadTimeout:       constants.WebUIReadTimeout,
		WriteTimeout:      constants.WebUIWriteTimeout,
		IdleTimeout:       constants.WebUIIdleTimeout,
	}

	tlsMode := os.Getenv("SEAWISE_TLS")
	if tlsMode == "auto" {
		certFile := filepath.Join(paths.DataDir(), "tls-cert.pem")
		keyFile := filepath.Join(paths.DataDir(), "tls-key.pem")

		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			slog.Info("Generating self-signed TLS certificate", "component", "webui")
			if err := generateSelfSignedCert(certFile, keyFile); err != nil {
				slog.Warn("Failed to generate TLS cert, falling back to HTTP", "component", "webui", "error", err)
				tlsMode = ""
			}
		}

		if tlsMode == "auto" {
			slog.Info("Web UI listening with self-signed TLS", "component", "webui", "bind_addr", bindAddr, "port", port, "protocol", "https") // #nosec G706
			go func() {
				if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
					slog.Error("Web UI TLS failed, tunnel continues running", "component", "webui", "error", err)
				}
			}()
			return srv
		}
	}

	slog.Info("Web UI listening", "component", "webui", "bind_addr", bindAddr, "port", port, "protocol", "http") // #nosec G706
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Web UI failed, tunnel continues running", "component", "webui", "error", err)
		}
	}()

	return srv
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	const prefix = "/static/"
	if len(r.URL.Path) <= len(prefix) {
		http.NotFound(w, r)
		return
	}
	name := r.URL.Path[len(prefix):]
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := templates.ReadFile("templates/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if _, err := w.Write(data); err != nil { // #nosec G705
		slog.Error("Failed to write response", "component", "static", "error", err)
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	data := struct {
		WebAppURL    string
		PairingState string
		Version      string
	}{
		WebAppURL: config.GetWebURL(),
		Version:   constants.Version,
	}

	s.mu.RLock()
	data.PairingState = s.pairingState
	s.mu.RUnlock()

	if err := indexTemplate.Execute(w, data); err != nil {
		slog.Error("Template render error", "component", "webui", "error", err)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"status":  "ok",
		"version": constants.Version,
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	paired := s.pairingState == "paired"
	frpClient := s.frpClient
	s.mu.RUnlock()

	frpRunning := frpClient != nil && frpClient.IsRunning()

	body := map[string]interface{}{
		"paired":      paired,
		"frp_running": frpRunning,
		"version":     constants.Version,
	}
	if paired && frpRunning {
		body["status"] = "ready"
		writeJSON(w, body)
		return
	}
	body["status"] = "not_ready"
	writeJSONStatus(w, http.StatusServiceUnavailable, body)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := !s.auth.hasPassword()
	if s.auth.hasPassword() {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			authenticated = s.auth.validateSession(cookie.Value)
		}
	}

	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			hostname = constants.DefaultHostname
		}
	}

	s.mu.RLock()
	status := map[string]interface{}{
		"pairing_state":    s.pairingState,
		"default_hostname": hostname,
		"version":          constants.Version,
		"password_set":     s.auth.hasPassword(),
		"authenticated":    authenticated,
	}
	if s.latestVersion != "" {
		status["latest_version"] = s.latestVersion
	}

	if authenticated {
		status["pairing_code"] = s.pairingCode

		connStatus := s.connManager.GetStatus()
		status["connection"] = connStatus

		if s.frpClient != nil {
			status["frp_state"] = string(s.frpClient.State())
			status["frp_running"] = s.frpClient.IsRunning()
			status["frp_crash_count"] = s.frpClient.CrashCount()
		}

		if s.cfg != nil {
			status["server_id"] = s.cfg.ServerID
			status["server_name"] = s.cfg.ServerName
			status["user_id"] = s.cfg.UserID
			status["user_email"] = s.cfg.UserEmail
		}
	}
	s.mu.RUnlock()

	writeJSON(w, status)
}

func generateSelfSignedCert(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SeaWise Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certOut, err := os.Create(certFile) // #nosec G304
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}
