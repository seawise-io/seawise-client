package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/certs"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/connection"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/frp"
	"github.com/seawise/client/internal/paths"
	"github.com/seawise/client/internal/validation"
)

//go:embed templates/*
var templates embed.FS

var indexTemplate = template.Must(template.ParseFS(templates, "templates/index.html"))

// writeJSON encodes data as JSON to the response writer.
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode JSON response", "component", "webui", "error", err)
	}
}

// writeJSONStatus encodes data as JSON with the given HTTP status code.
func writeJSONStatus(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode JSON response", "component", "webui", "error", err)
	}
}

// Server owns all runtime state for the SeaWise client.
type Server struct {
	mu          sync.RWMutex
	shutdownCtx context.Context
	cancel      context.CancelFunc

	apiClient   *api.Client
	cfg         *config.Config
	frpClient   *frp.Client
	connManager *connection.Manager
	certManager *certs.CertManager
	auth        *authManager

	pairingCode       string
	pairingDeviceCode string
	pairingState      string // "none", "pending", "approved", "paired"
	pairingCancel     context.CancelFunc
	e2eTLSEnabled     bool
	latestVersion     string

	serviceCache     map[string]string // subdomain -> serviceID
	lastHealthStatus map[string]string // serviceID -> "online"/"offline"

	restartInProgress atomic.Bool
}

// Run starts the SeaWise client server with web UI.
func Run(port int) {
	s := &Server{
		pairingState:     "none",
		auth:             newAuthManager(),
		serviceCache:     make(map[string]string),
		lastHealthStatus: make(map[string]string),
	}
	s.run(port)
}

func (s *Server) run(port int) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info("SeaWise Client starting", "component", "main", "version", constants.Version)

	ctx, cancel := context.WithCancel(context.Background())
	s.shutdownCtx = ctx
	s.cancel = cancel

	apiClient, err := api.New(config.GetAPIURL(nil))
	if err != nil {
		slog.Error("Invalid API URL", "component", "main", "error", err)
		os.Exit(1)
	}
	s.apiClient = apiClient

	s.connManager = connection.NewManager(connection.DefaultConfig())
	s.connManager.SetCallbacks(
		func(old, newState connection.State) {
			slog.Info("Connection state changed", "component", "main", "old_state", string(old), "new_state", string(newState))
			// Clear health cache on reconnection so services get re-reported
			if newState == connection.StateConnected && (old == connection.StateReconnecting || old == connection.StateConnecting) {
				s.mu.Lock()
				s.lastHealthStatus = make(map[string]string)
				s.mu.Unlock()
				go func() {
					time.Sleep(5 * time.Second)
					s.checkAndReportHealth()
				}()
			}
		},
		func() {
			slog.Info("Unpair requested by server", "component", "main")
			s.handleUnpairInternal()
		},
	)

	if config.Exists() {
		var err error
		s.cfg, err = config.Load()
		if err != nil {
			slog.Warn("Failed to load config", "component", "main", "error", err)
			s.pairingState = "none"
			s.connManager.SetState(connection.StateDisconnected)
		} else {
			slog.Info("Already paired as server", "component", "main", "server_name", s.cfg.ServerName, "server_id", s.cfg.ServerID)
			storedClient, apiErr := api.New(s.cfg.APIURL)
			if apiErr != nil {
				slog.Warn("Invalid stored API URL", "component", "main", "error", apiErr)
			} else {
				s.apiClient = storedClient
			}
			s.apiClient.SetFRPToken(s.cfg.FRPToken)
			s.pairingState = "paired"
			s.connManager.SetState(connection.StateConnecting)
			s.startServices(ctx)
		}
	} else {
		s.pairingState = "none"
		s.connManager.SetState(connection.StateUnpaired)
	}

	srv := s.startWebUI(ctx, port)

	slog.Info("SeaWise Client running", "component", "main")
	slog.Info("Open web UI to manage this server", "component", "main", "url", fmt.Sprintf("http://localhost:%d", port))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	slog.Info("Shutting down...", "component", "main")

	cancel()

	httpShutdownCtx, httpShutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
	defer httpShutdownRelease()
	if err := srv.Shutdown(httpShutdownCtx); err != nil {
		slog.Error("HTTP server shutdown error", "component", "main", "error", err)
	}

	s.mu.RLock()
	shutdownCfg := s.cfg
	shutdownAPIClient := s.apiClient
	s.mu.RUnlock()
	if shutdownCfg != nil && shutdownAPIClient != nil {
		if err := shutdownAPIClient.MarkOffline(shutdownCfg.ServerID); err != nil {
			slog.Error("Failed to notify API of shutdown", "component", "main", "error", err)
		} else {
			slog.Info("Notified API: server going offline", "component", "main")
		}
	}

	s.connManager.Stop()
	s.auth.Stop()
	s.mu.RLock()
	client := s.frpClient
	s.mu.RUnlock()
	if client != nil {
		if err := client.Stop(); err != nil {
			slog.Error("FRP stop error", "component", "frp", "error", err)
		}
	}
	slog.Info("Shutdown complete", "component", "main")
}

func (s *Server) startServices(ctx context.Context) {
	frpServerAddr := s.cfg.FRPServerAddr
	if frpServerAddr == "" {
		frpServerAddr = os.Getenv("FRP_SERVER_ADDR")
	}
	if frpServerAddr == "" {
		frpServerAddr = constants.DockerHostInternal
	}

	frpServerPort := s.cfg.FRPServerPort
	if frpServerPort == 0 {
		frpServerPort = constants.DefaultFRPServerPort
	}

	frpToken := s.cfg.FRPToken

	slog.Info("Connecting to FRP server", "component", "frp", "addr", frpServerAddr, "port", frpServerPort, "tls", s.cfg.FRPUseTLS) // #nosec G706 -- config values, not user input

	certStatus, err := s.apiClient.GetCertStatus()
	if err != nil {
		slog.Error("Failed to check E2E TLS status", "component", "e2e_tls", "error", err)
		s.e2eTLSEnabled = false
	} else {
		s.e2eTLSEnabled = certStatus.E2ETLSEnabled
		slog.Info("E2E TLS status", "component", "e2e_tls", "enabled", s.e2eTLSEnabled)
	}

	if s.e2eTLSEnabled {
		s.certManager = certs.New(paths.DataDir())
		if err := s.certManager.EnsureDir(); err != nil {
			slog.Error("Failed to create certs dir", "component", "e2e_tls", "error", err)
			s.e2eTLSEnabled = false
		}
	}

	s.frpClient = frp.New(frp.Config{
		ServerAddr: frpServerAddr,
		ServerPort: frpServerPort,
		Token:      frpToken,
		ServerID:   s.cfg.ServerID,
		UseTLS:     s.cfg.FRPUseTLS,
	})

	s.frpClient.SetOnStateChange(func(state frp.ProcessState) {
		slog.Info("FRP process state changed", "component", "main", "state", string(state))
		if state == frp.ProcessCrashed {
			s.connManager.SetState(connection.StateReconnecting)
			go s.handleFRPCrash()
		}
	})

	slog.Info("FRP client initialized, ready to add services", "component", "frp")

	services, err := s.apiClient.ListServices(s.cfg.ServerID)
	if err != nil {
		slog.Error("Failed to load services from API", "component", "main", "error", err)
	} else if len(services) > 0 {
		slog.Info("Loading services from API", "component", "main", "count", len(services))
		for _, svc := range services {
			frpSvc := frp.Service{
				Name:      svc.Name,
				LocalIP:   svc.Host,
				LocalPort: svc.Port,
				Subdomain: svc.Subdomain,
			}

			s.configureServiceTLS(&frpSvc, svc.Subdomain)
			s.frpClient.AddServiceWithoutRestart(frpSvc)
		}
	}

	if err := s.frpClient.Start(); err != nil {
		slog.Error("Failed to start FRP", "component", "frp", "error", err)
		s.connManager.SetState(connection.StateReconnecting)
	} else {
		s.connManager.SetState(connection.StateConnected)
	}

	go s.heartbeatLoop(ctx)
	go s.serviceSyncLoop(ctx)
	go s.serviceHealthLoop(ctx)
	go s.checkForUpdates(ctx)
}

// heartbeatLoop sends heartbeats and handles responses.
func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(constants.StatusPollInterval)
	defer ticker.Stop()

	s.sendHeartbeat(ticker)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping heartbeat loop", "component", "heartbeat", "reason", "shutdown")
			return
		case <-ticker.C:
			s.sendHeartbeat(ticker)

			s.mu.RLock()
			client := s.frpClient
			s.mu.RUnlock()
			if client != nil && client.State() == frp.ProcessCrashed {
				s.handleFRPCrash()
			}
		}
	}
}

func (s *Server) sendHeartbeat(ticker *time.Ticker) {
	s.mu.RLock()
	currentCfg := s.cfg
	client := s.frpClient
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil {
		return
	}

	// Consider connected if process is running or has a connection ID (no-service case)
	frpConnected := client != nil && (client.IsRunning() || client.ConnectionID() != "")
	serviceCount := 0
	connectionID := ""
	if client != nil {
		serviceCount = client.ServiceCount()
		connectionID = client.ConnectionID()
	}

	result := currentAPIClient.Heartbeat(currentCfg.ServerID, frpConnected, serviceCount, constants.Version, connectionID)

	if result.ShouldUnpair {
		slog.Info("Server requests unpair", "component", "heartbeat")
		s.connManager.HeartbeatFailed(true)
		return
	}

	if result.Superseded {
		slog.Warn("Connection superseded — restarting FRP with new connection ID", "component", "heartbeat")
		// Don't give up permanently. Reset connection ID and restart FRP so the
		// next Login writes the new ID to the DB. If genuinely superseded by another
		// client, the consecutive failure counter will eventually trigger disconnect.
		// If it was a race condition (startup timing), the retry succeeds immediately.
		if client != nil {
			client.ResetConnectionID()
			if err := client.Stop(); err != nil {
				slog.Error("Failed to stop FRP for restart", "component", "heartbeat", "error", err)
			}
			go func() {
				time.Sleep(2 * time.Second)
				s.mu.RLock()
				cfg := s.cfg
				s.mu.RUnlock()
				if cfg != nil {
					if err := client.Start(); err != nil {
						slog.Error("Failed to restart FRP after superseded", "component", "heartbeat", "error", err)
					}
				}
			}()
		}
		return
	}

	if result.Error != nil {
		slog.Warn("Heartbeat failed", "component", "heartbeat", "error", result.Error)
		s.connManager.HeartbeatFailed(false)
		return
	}

	s.connManager.HeartbeatOK()

	// Adopt server-recommended heartbeat interval (clamped to 10s-5min)
	if result.Response != nil && result.Response.NextHeartbeatMs > 0 {
		interval := time.Duration(result.Response.NextHeartbeatMs) * time.Millisecond
		if interval < 10*time.Second {
			interval = 10 * time.Second
		}
		if interval > 5*time.Minute {
			interval = 5 * time.Minute
		}
		ticker.Reset(interval)
	}

	if result.Response != nil && result.Response.GapSeconds > 30 {
		slog.Info("Server detected heartbeat gap, clearing health cache", "component", "heartbeat", "gap_seconds", result.Response.GapSeconds)
		s.mu.Lock()
		s.lastHealthStatus = make(map[string]string)
		s.mu.Unlock()
		// Trigger immediate health check after short delay (network may need a moment)
		go func() {
			time.Sleep(5 * time.Second)
			s.checkAndReportHealth()
		}()
	}

	// Handle shard migration
	if result.Response != nil && result.Response.Status == "migrate" && result.Response.MigrateTo != nil {
		migrate := result.Response.MigrateTo
		slog.Info("Migration requested", "component", "heartbeat", "addr", migrate.FRPServerAddr, "port", migrate.FRPServerPort, "shard", migrate.ShardID)

		s.mu.Lock()
		s.cfg.FRPServerAddr = migrate.FRPServerAddr
		s.cfg.FRPServerPort = migrate.FRPServerPort
		if err := s.cfg.Save(); err != nil {
			slog.Error("Failed to save migrated config", "component", "heartbeat", "error", err)
		}
		s.mu.Unlock()

		if client != nil {
			if err := client.UpdateServer(migrate.FRPServerAddr, migrate.FRPServerPort); err != nil {
				slog.Warn("Rejected migration to untrusted server", "component", "heartbeat", "error", err)
			} else {
				client.ResetConnectionID()
				if err := client.Restart(); err != nil {
					slog.Error("Migration restart failed", "component", "heartbeat", "error", err)
				} else {
					slog.Info("Migration complete", "component", "heartbeat", "shard", migrate.ShardID)
					s.mu.Lock()
					s.lastHealthStatus = make(map[string]string)
					s.mu.Unlock()
				}
			}
		}
		return
	}

	// Self-heal stale FRP address
	if result.Response != nil && result.Response.Shard != nil && client != nil {
		shard := result.Response.Shard
		s.mu.RLock()
		storedAddr := s.cfg.FRPServerAddr
		storedPort := s.cfg.FRPServerPort
		s.mu.RUnlock()

		if shard.FRPServerAddr != storedAddr || shard.FRPServerPort != storedPort {
			slog.Info("Shard address changed", "component", "heartbeat",
				"old_addr", storedAddr, "old_port", storedPort,
				"new_addr", shard.FRPServerAddr, "new_port", shard.FRPServerPort)

			if err := client.UpdateServer(shard.FRPServerAddr, shard.FRPServerPort); err != nil {
				slog.Warn("Rejected shard update to untrusted server", "component", "heartbeat", "error", err)
			} else {
				s.mu.Lock()
				s.cfg.FRPServerAddr = shard.FRPServerAddr
				s.cfg.FRPServerPort = shard.FRPServerPort
				if err := s.cfg.Save(); err != nil {
					slog.Error("Failed to save updated config", "component", "heartbeat", "error", err)
				}
				s.mu.Unlock()

				client.ResetConnectionID()
				if err := client.Restart(); err != nil {
					slog.Error("FRP restart after address update failed", "component", "heartbeat", "error", err)
				} else {
					slog.Info("FRP reconnected to updated shard address", "component", "heartbeat")
					s.mu.Lock()
					s.lastHealthStatus = make(map[string]string)
					s.mu.Unlock()
				}
			}
		}
	}
}

// serviceSyncLoop periodically syncs services with the API.
func (s *Server) serviceSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(constants.ServicePollInterval)
	defer ticker.Stop()

	select {
	case <-ctx.Done():
		return
	case <-time.After(constants.StartupDelay):
	}
	s.syncServices()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping service sync loop", "component", "sync", "reason", "shutdown")
			return
		case <-ticker.C:
			s.syncServices()
		}
	}
}

// serviceHealthLoop probes each service and reports status changes to the API.
func (s *Server) serviceHealthLoop(ctx context.Context) {
	ticker := time.NewTicker(constants.StatusPollInterval)
	defer ticker.Stop()

	select {
	case <-ctx.Done():
		return
	case <-time.After(constants.StartupDelay + 5*time.Second):
	}

	for {
		s.checkAndReportHealth()

		select {
		case <-ctx.Done():
			slog.Info("Stopping health check loop", "component", "health", "reason", "shutdown")
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) checkAndReportHealth() {
	s.mu.RLock()
	currentCfg := s.cfg
	client := s.frpClient
	currentAPIClient := s.apiClient
	serviceCache := s.serviceCache
	s.mu.RUnlock()

	if currentCfg == nil || client == nil {
		return
	}

	frpServices := client.GetServices()
	if len(frpServices) == 0 {
		return
	}

	if len(serviceCache) == 0 {
		return
	}

	var changed []api.ServiceHealthStatus
	for _, svc := range frpServices {
		id, ok := serviceCache[svc.Subdomain]
		if !ok {
			continue
		}

		status := "offline"
		host := frp.TranslateLocalhost(svc.LocalIP)
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", svc.LocalPort))
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			_ = conn.Close()
			status = "online"
		}

		s.mu.RLock()
		lastStatus := s.lastHealthStatus[id]
		s.mu.RUnlock()

		if lastStatus != status {
			changed = append(changed, api.ServiceHealthStatus{
				ID:     id,
				Status: status,
			})
			s.mu.Lock()
			s.lastHealthStatus[id] = status
			s.mu.Unlock()
		}
	}

	if len(changed) > 0 {
		slog.Info("Service health status changed, reporting", "component", "health", "changed_count", len(changed))
		if err := currentAPIClient.ReportServiceHealth(currentCfg.ServerID, changed); err != nil {
			slog.Error("Failed to report health", "component", "health", "error", err)
			s.mu.Lock()
			for _, svc := range changed {
				delete(s.lastHealthStatus, svc.ID)
			}
			s.mu.Unlock()
		}
	}
}

// checkForUpdates periodically checks GitHub Releases for a newer client version.
func (s *Server) checkForUpdates(ctx context.Context) {
	if constants.Version == "dev" || strings.HasPrefix(constants.Version, "dev-") {
		return
	}

	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return
	}

	s.fetchLatestVersion()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.fetchLatestVersion()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) fetchLatestVersion() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.github.com/repos/seawise-io/seawise-client/releases/latest", nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		slog.Error("Failed to parse release info", "component", "update", "error", err)
		return
	}

	if release.TagName != "" && release.TagName != constants.Version {
		s.mu.Lock()
		s.latestVersion = release.TagName
		s.mu.Unlock()
		slog.Info("New version available", "component", "update", "latest", release.TagName, "current", constants.Version)
	}
}

// ensureServiceCert ensures a TLS certificate exists for the service.
func (s *Server) ensureServiceCert(subdomain string) (certPath, keyPath string, err error) {
	if s.certManager == nil {
		return "", "", nil
	}

	if !validation.IsValidHost(subdomain) || strings.ContainsAny(subdomain, ".:[]") {
		return "", "", fmt.Errorf("invalid subdomain: %s", subdomain)
	}

	subdomainHost := os.Getenv("SUBDOMAIN_HOST")
	if subdomainHost == "" {
		subdomainHost = constants.DefaultSubdomainHost
	}
	domain := subdomain + "." + subdomainHost

	if s.certManager.CertExists(domain) && !s.certManager.NeedsRenewal(domain) {
		cert, key, err := s.certManager.GetCertPaths(domain)
		if err != nil {
			return "", "", err
		}
		return cert, key, nil
	}

	slog.Info("Requesting certificate", "component", "e2e_tls", "domain", domain) // #nosec G706 -- domain from API config

	key, err := s.certManager.GenerateKey()
	if err != nil {
		return "", "", err
	}

	csrPEM, err := s.certManager.CreateCSR(key, domain)
	if err != nil {
		return "", "", err
	}

	certResp, err := s.apiClient.RequestCertificate(subdomain, csrPEM)
	if err != nil {
		return "", "", err
	}

	keyPath, err = s.certManager.SaveKey(key, domain)
	if err != nil {
		return "", "", err
	}

	certPath, err = s.certManager.SaveCert([]byte(certResp.Certificate), domain)
	if err != nil {
		return "", "", err
	}

	slog.Info("Certificate saved", "component", "e2e_tls", "domain", domain, "expires_at", certResp.ExpiresAt) // #nosec G706 -- domain from API config
	return certPath, keyPath, nil
}

// configureServiceTLS sets up E2E TLS on a FRP service.
func (s *Server) configureServiceTLS(frpSvc *frp.Service, subdomain string) {
	if !s.e2eTLSEnabled || s.certManager == nil {
		return
	}
	certPath, keyPath, err := s.ensureServiceCert(subdomain)
	if err != nil {
		slog.Error("Failed to get cert", "component", "e2e_tls", "subdomain", subdomain, "error", err)
		return
	}
	if certPath != "" && keyPath != "" {
		frpSvc.UseE2ETLS = true
		frpSvc.CertPath = certPath
		frpSvc.KeyPath = keyPath
		slog.Info("E2E TLS configured for service", "component", "e2e_tls", "subdomain", subdomain)
	}
}

// syncServices fetches services from API and syncs with local FRP config.
func (s *Server) syncServices() {
	s.mu.RLock()
	currentCfg := s.cfg
	client := s.frpClient
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil || client == nil {
		return
	}

	apiServices, err := currentAPIClient.ListServices(currentCfg.ServerID)
	if err != nil {
		slog.Error("Failed to fetch services", "component", "sync", "error", err)
		return
	}

	s.mu.Lock()
	s.serviceCache = make(map[string]string, len(apiServices))
	for _, svc := range apiServices {
		s.serviceCache[svc.Subdomain] = svc.ID
	}
	s.mu.Unlock()

	frpServices := make([]frp.Service, len(apiServices))
	for i, svc := range apiServices {
		frpSvc := frp.Service{
			Name:      svc.Name,
			LocalIP:   svc.Host,
			LocalPort: svc.Port,
			Subdomain: svc.Subdomain,
		}

		s.configureServiceTLS(&frpSvc, svc.Subdomain)
		frpServices[i] = frpSvc
	}

	added, removed, err := client.SyncServices(frpServices)
	if err != nil {
		slog.Error("Failed to sync services", "component", "sync", "error", err)
		return
	}

	if len(added) > 0 {
		slog.Info("Added services", "component", "sync", "services", added)
	}
	if len(removed) > 0 {
		slog.Info("Removed services", "component", "sync", "services", removed)
	}
}

// handleFRPCrash restarts FRP with exponential backoff.
func (s *Server) handleFRPCrash() {
	if !s.restartInProgress.CompareAndSwap(false, true) {
		slog.Info("Restart already in progress, skipping", "component", "frp_recovery")
		return
	}
	defer s.restartInProgress.Store(false)

	s.mu.RLock()
	client := s.frpClient
	currentCfg := s.cfg
	s.mu.RUnlock()

	if client == nil || currentCfg == nil {
		return
	}

	delay := s.connManager.CalculateBackoff()
	slog.Info("Waiting before restart", "component", "frp_recovery", "delay", delay)

	timer := time.NewTimer(delay)
	select {
	case <-timer.C:
	case <-s.shutdownCtx.Done():
		timer.Stop()
		slog.Info("FRP recovery cancelled", "component", "frp_recovery", "reason", "shutdown")
		return
	}

	if s.connManager.State() == connection.StateUnpaired {
		slog.Info("FRP recovery cancelled", "component", "frp_recovery", "reason", "client unpaired")
		return
	}

	s.mu.RLock()
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentAPIClient != nil {
		if err := currentAPIClient.MarkOffline(currentCfg.ServerID); err != nil {
			slog.Error("Failed to mark offline", "component", "frp_recovery", "error", err)
		}
	}

	if currentAPIClient != nil {
		services, err := currentAPIClient.ListServices(currentCfg.ServerID)
		if err != nil {
			slog.Error("Failed to reload services", "component", "frp_recovery", "error", err)
		} else if len(services) > 0 {
			var frpServices []frp.Service
			for _, svc := range services {
				frpSvc := frp.Service{
					Name:      svc.Name,
					LocalIP:   svc.Host,
					LocalPort: svc.Port,
					Subdomain: svc.Subdomain,
				}
				s.configureServiceTLS(&frpSvc, svc.Subdomain)
				frpServices = append(frpServices, frpSvc)
			}
			client.SetServices(frpServices)
			slog.Info("Reloaded services from API", "component", "frp_recovery", "count", len(frpServices))
		}
	}

	_ = client.Stop()
	client.ResetConnectionID()
	if err := client.Start(); err != nil {
		slog.Error("FRP restart failed", "component", "frp_recovery", "error", err)
		// Will be retried on next heartbeat cycle
	} else {
		slog.Info("FRP restart successful", "component", "frp_recovery")
		s.connManager.ResetBackoff()
		client.ResetCrashCount()
		s.connManager.SetState(connection.StateConnected)

		s.mu.Lock()
		s.lastHealthStatus = make(map[string]string)
		s.mu.Unlock()
	}
}

func (s *Server) handleUnpairInternal() {
	s.mu.Lock()
	if s.frpClient != nil {
		_ = s.frpClient.Stop()
		s.frpClient = nil
	}

	if err := config.Delete(); err != nil {
		slog.Error("Failed to delete config", "component", "unpair", "error", err)
	}
	s.cfg = nil
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	slog.Info("Client reset, please re-pair", "component", "unpair")
}

func (s *Server) startWebUI(ctx context.Context, port int) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/auth/set-password", s.handleAuthSetPassword)
	// Password removal disabled — password is mandatory (set on first run)

	mux.HandleFunc("/static/", handleStatic)
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/pair/start", s.handlePairStart)
	mux.HandleFunc("/api/pair/poll", s.handlePairPoll)
	mux.HandleFunc("/api/pair/cancel", s.handlePairCancel)
	mux.HandleFunc("/api/services/add", s.handleAddService)
	mux.HandleFunc("/api/services/list", s.handleListServices)
	mux.HandleFunc("/api/services/delete", s.handleDeleteService)
	mux.HandleFunc("/api/unpair", s.handleUnpair)

	bindAddr := os.Getenv("SEAWISE_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	if (bindAddr == "0.0.0.0" || bindAddr == "::") && !s.auth.hasPassword() {
		slog.Warn("Web UI is listening on all interfaces without a password", "component", "webui")
		slog.Info("Set a password in Settings if you want to restrict access", "component", "webui")
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
			slog.Info("Web UI listening with self-signed TLS", "component", "webui", "bind_addr", bindAddr, "port", port, "protocol", "https") // #nosec G706 -- config values
			go func() {
				if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
					slog.Error("Web UI TLS failed, tunnel continues running", "component", "webui", "error", err)
				}
			}()
			return srv
		}
	}

	slog.Info("Web UI listening", "component", "webui", "bind_addr", bindAddr, "port", port, "protocol", "http") // #nosec G706 -- config values
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
	// Non-sensitive data only — user identity is fetched via authenticated API calls in JS.
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Determine if caller is authenticated (password set + valid session)
	authenticated := !s.auth.hasPassword() // No password = everyone is "authenticated"
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
	// Base status — safe for unauthenticated callers
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

	// Sensitive fields only for authenticated callers.
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

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w, map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		ServerName string `json:"server_name"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		req.ServerName = "My Server"
	}

	if req.ServerName == "" {
		req.ServerName = "My Server"
	}
	// Limit server name length to prevent abuse
	if len(req.ServerName) > 100 {
		req.ServerName = req.ServerName[:100]
	}

	result, err := s.apiClient.RequestPairing(req.ServerName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to request pairing code")})
		return
	}

	s.mu.Lock()
	if s.pairingCancel != nil {
		s.pairingCancel()
	}
	pairingCtx, pairingCancel := context.WithCancel(s.shutdownCtx)
	s.pairingCancel = pairingCancel
	s.pairingCode = result.UserCode
	s.pairingDeviceCode = result.DeviceCode
	s.pairingState = "pending"
	s.mu.Unlock()

	go s.pollForApproval(pairingCtx, result.DeviceCode)

	writeJSON(w, map[string]interface{}{
		"code":       result.UserCode,
		"expires_at": result.ExpiresAt,
	})
}

// pollForApproval polls for pairing approval using device_code.
func (s *Server) pollForApproval(ctx context.Context, deviceCode string) {
	ticker := time.NewTicker(constants.PairPollInterval)
	defer ticker.Stop()

	timeout := time.After(constants.WebPairTimeout)

	s.mu.RLock()
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Pairing poll stopped", "component", "pairing", "reason", "cancelled or shutdown")
			return
		case <-timeout:
			s.mu.Lock()
			s.pairingState = "none"
			s.pairingCode = ""
			s.pairingDeviceCode = ""
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.mu.RLock()
			currentState := s.pairingState
			s.mu.RUnlock()
			if currentState != "pending" {
				slog.Info("Pairing poll stopped", "component", "pairing", "reason", "cancelled")
				return
			}

			status, err := currentAPIClient.PollPairingStatus(deviceCode)
			if err != nil {
				slog.Warn("Pairing poll error", "component", "pairing", "error", err)
				continue
			}

			switch status {
			case "approved":
				result, err := currentAPIClient.CompletePairing(deviceCode)
				if err != nil {
					slog.Error("Failed to complete pairing", "component", "pairing", "error", err)
					s.mu.Lock()
					s.pairingState = "none"
					s.pairingDeviceCode = ""
					s.mu.Unlock()
					return
				}

				s.mu.Lock()
				s.cfg = &config.Config{
					ServerID:      result.Data.ServerID,
					ServerName:    result.Data.ServerName,
					FRPToken:      result.Data.FRPToken,
					FRPServerAddr: result.Data.FRPServerAddr,
					FRPServerPort: result.Data.FRPServerPort,
					FRPUseTLS:     result.Data.FRPUseTLS,
					APIURL:        s.apiClient.BaseURL(),
					UserID:        result.Data.UserID,
					UserEmail:     result.Data.UserEmail,
				}
				if err := s.cfg.Save(); err != nil {
					slog.Error("Failed to save config, aborting pairing", "component", "pairing", "error", err)
					s.pairingState = "none"
					s.pairingCode = ""
					s.pairingDeviceCode = ""
					s.mu.Unlock()
					return
				}

				s.apiClient.SetFRPToken(s.cfg.FRPToken)
				s.pairingState = "paired"
				s.pairingCode = ""
				s.pairingDeviceCode = ""
				serverName := s.cfg.ServerName
				s.mu.Unlock()

				slog.Info("Pairing successful", "component", "pairing", "server_name", serverName)

				// Start services
				s.connManager.SetState(connection.StateConnecting)
				s.startServices(s.shutdownCtx)
				return

			case "expired", "used":
				s.mu.Lock()
				s.pairingState = "none"
				s.pairingCode = ""
				s.pairingDeviceCode = ""
				s.mu.Unlock()
				return
			}
		}
	}
}

func (s *Server) handlePairCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	slog.Info("Pairing cancelled by user", "component", "pairing")
	writeJSON(w, map[string]string{"status": "cancelled"})
}

func (s *Server) handlePairPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	response := map[string]interface{}{
		"state": s.pairingState,
		"code":  s.pairingCode,
	}

	// Add connection info if paired
	response["connection_state"] = string(s.connManager.State())
	s.mu.RUnlock()

	writeJSON(w, response)
}

func (s *Server) handleAddService(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	isPaired := s.pairingState == "paired" && s.cfg != nil
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	client := s.frpClient
	s.mu.RUnlock()

	if !isPaired {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Not paired yet. Connect to SeaWise first."})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w, map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		Name string `json:"name"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Invalid request body"})
		return
	}

	if !validation.IsValidServiceName(req.Name) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Invalid app name (must be 1-100 characters)"})
		return
	}
	if !validation.IsValidHost(req.Host) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Invalid host format (must be a valid hostname or IP)"})
		return
	}
	if err := validation.ValidateServiceHost(req.Host); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	if !validation.IsValidPort(req.Port) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Invalid port (must be 1-65535)"})
		return
	}

	existingServices, err := currentAPIClient.ListServices(currentCfg.ServerID)
	if err == nil {
		for _, existing := range existingServices {
			if strings.EqualFold(existing.Name, req.Name) {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]string{"error": "An app with that name already exists"})
				return
			}
		}
	}

	svc, err := currentAPIClient.RegisterService(currentCfg.ServerID, req.Name, req.Host, req.Port)
	if err != nil {
		slog.Error("Failed to register service", "component", "webui", "service_name", req.Name, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to register app")})
		return
	}

	slog.Info("Registered service", "component", "webui", "service_name", req.Name, "subdomain", svc.Subdomain)

	var tunnelWarning string
	if client != nil {
		frpSvc := frp.Service{
			Name:      req.Name,
			LocalIP:   req.Host,
			LocalPort: req.Port,
			Subdomain: svc.Subdomain,
		}

		s.configureServiceTLS(&frpSvc, svc.Subdomain)
		if err := client.AddService(frpSvc); err != nil {
			slog.Warn("Failed to add to FRP tunnel", "component", "webui", "error", err)
			tunnelWarning = "App registered but tunnel update pending. It will sync automatically."
		} else {
			slog.Info("Added to FRP tunnel", "component", "webui", "service_name", req.Name, "subdomain", svc.Subdomain)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"success":   true,
		"service":   svc,
		"subdomain": svc.Subdomain,
	}
	if tunnelWarning != "" {
		response["warning"] = tunnelWarning
	}
	writeJSON(w, response)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Not paired yet"})
		return
	}

	services, err := currentAPIClient.ListServices(currentCfg.ServerID)
	if err != nil {
		slog.Error("Failed to list services", "component", "webui", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to list apps")})
		return
	}

	writeJSON(w, map[string]interface{}{
		"services": services,
	})
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	client := s.frpClient
	s.mu.RUnlock()

	if currentCfg == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Not paired yet"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w, map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		ServiceID   string `json:"service_id"`
		ServiceName string `json:"service_name"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.ServiceID == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "service_id is required"})
		return
	}

	if err := currentAPIClient.DeleteService(currentCfg.ServerID, req.ServiceID); err != nil {
		slog.Error("Failed to delete service", "component", "webui", "service_id", req.ServiceID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to delete app")})
		return
	}

	slog.Info("Deleted service", "component", "webui", "service_name", req.ServiceName, "service_id", req.ServiceID)

	if client != nil && req.ServiceName != "" {
		if err := client.RemoveService(req.ServiceName); err != nil {
			slog.Warn("Failed to remove from FRP tunnel", "component", "webui", "error", err)
		} else {
			slog.Info("Removed from FRP tunnel", "component", "webui", "service_name", req.ServiceName)
		}
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
	})
}

func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	s.connManager.SetState(connection.StateUnpaired)

	s.mu.RLock()
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg != nil {
		if err := currentAPIClient.DeleteServer(currentCfg.ServerID); err != nil {
			slog.Warn("Failed to delete server from API", "component", "webui", "error", err)
		} else {
			slog.Info("Server removed from dashboard", "component", "webui")
		}
	}

	s.handleUnpairInternal()

	writeJSON(w, map[string]interface{}{
		"success": true,
	})
}

// generateSelfSignedCert creates a self-signed ECDSA P-256 certificate.
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
