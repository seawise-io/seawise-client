package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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

// indexTemplate is parsed once at package init, not per request
var indexTemplate = template.Must(template.ParseFS(templates, "templates/index.html"))

// writeJSON encodes data as JSON to the response writer with error handling.
// Logs encoding failures which can occur if the client disconnects mid-response.
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[WebUI] Failed to encode JSON response: %v", err)
	}
}

// writeJSONStatus encodes data as JSON with a specific HTTP status code.
func writeJSONStatus(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[WebUI] Failed to encode JSON response: %v", err)
	}
}

// Server owns all runtime state for the SeaWise client.
// All fields are protected by mu for concurrent access.
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

	pairingCode       string // user_code (shown to user)
	pairingDeviceCode string // device_code (used for polling, never shown)
	pairingState      string // "none", "pending", "approved", "paired"
	e2eTLSEnabled  bool   // Whether the server supports E2E TLS
	latestVersion  string // Latest available version from GitHub Releases

	// Health check caches - only report changes to minimize API calls
	serviceCache     map[string]string // subdomain → serviceID
	lastHealthStatus map[string]string // serviceID → "online"/"offline"

	restartInProgress atomic.Bool // Dedup concurrent handleFRPCrash calls
}

// Run starts the SeaWise client server with web UI.
// This is the public entry point called from main.go.
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
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("SeaWise Client %s starting...", constants.Version)

	// Create root context that gets cancelled on shutdown signal.
	// All goroutines use this context to know when to exit.
	ctx, cancel := context.WithCancel(context.Background())
	s.shutdownCtx = ctx
	s.cancel = cancel

	// Initialize API client
	s.apiClient = api.New(config.GetAPIURL(nil))

	// Initialize connection manager with production-ready defaults
	s.connManager = connection.NewManager(connection.DefaultConfig())
	s.connManager.SetCallbacks(
		func(old, newState connection.State) {
			log.Printf("[Main] Connection state changed: %s -> %s", old, newState)
		},
		func(attempt int) error {
			log.Printf("[Main] Reconnection attempt %d", attempt)
			return s.reconnectFRP()
		},
		func() {
			log.Println("[Main] Unpair requested by server")
			s.handleUnpairInternal()
		},
	)

	// Check if already paired
	if config.Exists() {
		var err error
		s.cfg, err = config.Load()
		if err != nil {
			log.Printf("Warning: Failed to load config: %v", err)
			s.pairingState = "none"
			s.connManager.SetState(connection.StateDisconnected)
		} else {
			log.Printf("Already paired as server: %s (ID: %s)", s.cfg.ServerName, s.cfg.ServerID)
			// Re-initialize API client with the stored URL (may differ from default)
			s.apiClient = api.New(s.cfg.APIURL)
			s.apiClient.SetFRPToken(s.cfg.FRPToken)
			s.pairingState = "paired"
			s.connManager.SetState(connection.StateConnecting)
			s.startServices(ctx)
		}
	} else {
		s.pairingState = "none"
		s.connManager.SetState(connection.StateUnpaired)
	}

	// Start web UI server
	srv := s.startWebUI(ctx, port)

	log.Println("SeaWise Client running")
	log.Printf("Open http://localhost:%d to manage this server", port)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	// Cancel root context — all goroutines will begin exiting
	cancel()

	// Gracefully shut down the HTTP server (give in-flight requests 5s to finish)
	httpShutdownCtx, httpShutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
	defer httpShutdownRelease()
	if err := srv.Shutdown(httpShutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Notify API that we're going offline (revokes sessions, marks offline)
	s.mu.RLock()
	shutdownCfg := s.cfg
	shutdownAPIClient := s.apiClient
	s.mu.RUnlock()
	if shutdownCfg != nil && shutdownAPIClient != nil {
		if err := shutdownAPIClient.MarkOffline(shutdownCfg.ServerID); err != nil {
			log.Printf("Failed to notify API of shutdown: %v", err)
		} else {
			log.Println("Notified API: server going offline")
		}
	}

	s.connManager.Stop()
	s.auth.Stop() // Stop auth cleanup goroutine
	s.mu.RLock()
	client := s.frpClient
	s.mu.RUnlock()
	if client != nil {
		if err := client.Stop(); err != nil {
			log.Printf("FRP stop error: %v", err)
		}
	}
	log.Println("Shutdown complete")
}

func (s *Server) startServices(ctx context.Context) {
	// Get FRP server address from config, fallback to env, then default
	frpServerAddr := s.cfg.FRPServerAddr
	if frpServerAddr == "" {
		frpServerAddr = os.Getenv("FRP_SERVER_ADDR")
	}
	if frpServerAddr == "" {
		frpServerAddr = constants.DockerHostInternal
	}

	// Get FRP server port from config, fallback to default
	frpServerPort := s.cfg.FRPServerPort
	if frpServerPort == 0 {
		frpServerPort = constants.DefaultFRPServerPort
	}

	// Get FRP token from config
	frpToken := s.cfg.FRPToken

	log.Printf("[FRP] Connecting to %s:%d (TLS: %v)", frpServerAddr, frpServerPort, s.cfg.FRPUseTLS)

	// Check if server supports E2E TLS
	certStatus, err := s.apiClient.GetCertStatus()
	if err != nil {
		log.Printf("[E2E TLS] Failed to check status: %v", err)
		s.e2eTLSEnabled = false
	} else {
		s.e2eTLSEnabled = certStatus.E2ETLSEnabled
		log.Printf("[E2E TLS] Enabled: %v", s.e2eTLSEnabled)
	}

	// Initialize cert manager if E2E TLS is enabled
	if s.e2eTLSEnabled {
		s.certManager = certs.New(paths.DataDir())
		if err := s.certManager.EnsureDir(); err != nil {
			log.Printf("[E2E TLS] Failed to create certs dir: %v", err)
			s.e2eTLSEnabled = false
		}
	}

	// Initialize FRP client
	s.frpClient = frp.New(frp.Config{
		ServerAddr: frpServerAddr,
		ServerPort: frpServerPort,
		Token:      frpToken,
		UserID:     s.cfg.UserID,
		ServerID:   s.cfg.ServerID,
		UseTLS:     s.cfg.FRPUseTLS,
	})

	// Set up FRP process monitoring
	s.frpClient.SetOnStateChange(func(state frp.ProcessState) {
		log.Printf("[Main] FRP process state: %s", state)
		if state == frp.ProcessCrashed {
			// FRP crashed, trigger reconnection
			s.connManager.SetState(connection.StateReconnecting)
			go s.handleFRPCrash()
		}
	})

	log.Println("FRP client initialized, ready to add services")

	// Load existing services from API and add to FRP
	services, err := s.apiClient.ListServices(s.cfg.ServerID)
	if err != nil {
		log.Printf("Failed to load services from API: %v", err)
	} else if len(services) > 0 {
		log.Printf("Loading %d services from API", len(services))
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

	// Start FRP
	if err := s.frpClient.Start(); err != nil {
		log.Printf("Failed to start FRP: %v", err)
		s.connManager.SetState(connection.StateReconnecting)
	} else {
		s.connManager.SetState(connection.StateConnected)
	}

	// Start heartbeat loop
	go s.heartbeatLoop(ctx)

	// Start service sync loop (syncs with API to detect changes)
	go s.serviceSyncLoop(ctx)

	// Start service health check loop
	go s.serviceHealthLoop(ctx)

	// Start update checker (checks GitHub Releases every 24h)
	go s.checkForUpdates(ctx)
}

// heartbeatLoop sends heartbeats and handles responses.
// Exits when ctx is cancelled (shutdown).
func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(constants.StatusPollInterval)
	defer ticker.Stop()

	// Initial heartbeat
	s.sendHeartbeat()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Heartbeat] Stopping (shutdown)")
			return
		case <-ticker.C:
			s.sendHeartbeat()

			// Check if we need to restart FRP (crashed state)
			s.mu.RLock()
			client := s.frpClient
			s.mu.RUnlock()
			if client != nil && client.State() == frp.ProcessCrashed {
				s.handleFRPCrash()
			}
		}
	}
}

func (s *Server) sendHeartbeat() {
	s.mu.RLock()
	currentCfg := s.cfg
	client := s.frpClient
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil {
		return
	}

	// FRP is "connected" if the client is initialized (has a connection ID),
	// even if the process isn't running yet (no services to proxy).
	// Without this, the first service can never be registered: FRP doesn't start
	// because there are no services, but the API requires "online" to add services.
	frpConnected := client != nil && (client.IsRunning() || client.ConnectionID() != "")
	serviceCount := 0
	connectionID := ""
	if client != nil {
		serviceCount = client.ServiceCount()
		connectionID = client.ConnectionID()
	}

	result := currentAPIClient.Heartbeat(currentCfg.ServerID, frpConnected, serviceCount, constants.Version, connectionID)

	if result.ShouldUnpair {
		// Server says we should unpair (server was deleted)
		log.Println("[Heartbeat] Server requests unpair")
		s.connManager.HeartbeatFailed(true)
		return
	}

	if result.Superseded {
		// Another client connected with the same credentials
		// This means someone copied our config or we're being migrated
		log.Println("[Heartbeat] Connection superseded - another client is now active")
		log.Println("[Heartbeat] If this is unexpected, regenerate your server token from the dashboard")
		s.connManager.HeartbeatFailed(false)
		// Stop the FRP client to avoid competing with the new connection
		if client != nil {
			if err := client.Stop(); err != nil {
				log.Printf("[Heartbeat] Failed to stop FRP after superseded: %v", err)
			}
		}
		return
	}

	if result.Error != nil {
		log.Printf("[Heartbeat] Failed: %v", result.Error)
		s.connManager.HeartbeatFailed(false)
		return
	}

	// Success
	s.connManager.HeartbeatOK()

	// Log any gap detected by server
	if result.Response != nil && result.Response.GapSeconds > 30 {
		log.Printf("[Heartbeat] Server detected gap of %ds", result.Response.GapSeconds)
	}

	// Handle shard migration signal (draining shard → new shard)
	if result.Response != nil && result.Response.Status == "migrate" && result.Response.MigrateTo != nil {
		migrate := result.Response.MigrateTo
		log.Printf("[Heartbeat] Migration requested → %s:%d (shard %s)",
			migrate.FRPServerAddr, migrate.FRPServerPort, migrate.ShardID)

		// Update saved config so restarts use the new shard
		s.mu.Lock()
		s.cfg.FRPServerAddr = migrate.FRPServerAddr
		s.cfg.FRPServerPort = migrate.FRPServerPort
		if err := s.cfg.Save(); err != nil {
			log.Printf("[Heartbeat] Failed to save migrated config: %v", err)
		}
		s.mu.Unlock()

		// Graceful restart: update FRP server address and reconnect
		if client != nil {
			// SECURITY: Validate the migration target before updating
			if err := client.UpdateServer(migrate.FRPServerAddr, migrate.FRPServerPort); err != nil {
				log.Printf("[Heartbeat] SECURITY: Rejected migration to untrusted server: %v", err)
			} else {
				client.ResetConnectionID() // New shard = new session
				if err := client.Restart(); err != nil {
					log.Printf("[Heartbeat] Migration restart failed: %v", err)
				} else {
					log.Printf("[Heartbeat] Migration complete → connected to shard %s", migrate.ShardID)
					// Clear health cache so services get re-reported
					s.mu.Lock()
					s.lastHealthStatus = make(map[string]string)
					s.mu.Unlock()
				}
			}
		}
		return
	}

	// Self-heal stale FRP address (e.g., after infrastructure migration)
	// If the shard's current address differs from our stored address, update and reconnect
	if result.Response != nil && result.Response.Shard != nil && client != nil {
		shard := result.Response.Shard
		s.mu.RLock()
		storedAddr := s.cfg.FRPServerAddr
		storedPort := s.cfg.FRPServerPort
		s.mu.RUnlock()

		if shard.FRPServerAddr != storedAddr || shard.FRPServerPort != storedPort {
			log.Printf("[Heartbeat] Shard address changed: %s:%d → %s:%d",
				storedAddr, storedPort, shard.FRPServerAddr, shard.FRPServerPort)

			// SECURITY: Validate the new address before updating
			if err := client.UpdateServer(shard.FRPServerAddr, shard.FRPServerPort); err != nil {
				log.Printf("[Heartbeat] SECURITY: Rejected shard update to untrusted server: %v", err)
			} else {
				// Update saved config so restarts use the new address
				s.mu.Lock()
				s.cfg.FRPServerAddr = shard.FRPServerAddr
				s.cfg.FRPServerPort = shard.FRPServerPort
				if err := s.cfg.Save(); err != nil {
					log.Printf("[Heartbeat] Failed to save updated config: %v", err)
				}
				s.mu.Unlock()

				client.ResetConnectionID() // New shard address = new session
				if err := client.Restart(); err != nil {
					log.Printf("[Heartbeat] FRP restart after address update failed: %v", err)
				} else {
					log.Printf("[Heartbeat] FRP reconnected to updated shard address")
					// Clear health cache so services get re-reported
					s.mu.Lock()
					s.lastHealthStatus = make(map[string]string)
					s.mu.Unlock()
				}
			}
		}
	}
}

// serviceSyncLoop periodically syncs services with the API to detect remote changes.
// Exits when ctx is cancelled (shutdown).
func (s *Server) serviceSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(constants.ServicePollInterval)
	defer ticker.Stop()

	// Initial sync after a short delay (but respect shutdown)
	select {
	case <-ctx.Done():
		return
	case <-time.After(constants.StartupDelay):
	}
	s.syncServices()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Sync] Stopping (shutdown)")
			return
		case <-ticker.C:
			s.syncServices()
		}
	}
}

// serviceHealthLoop periodically checks if each service's host:port is reachable
// and reports the health status to the API.
func (s *Server) serviceHealthLoop(ctx context.Context) {
	ticker := time.NewTicker(constants.StatusPollInterval) // 10 seconds
	defer ticker.Stop()

	// Wait for initial startup
	select {
	case <-ctx.Done():
		return
	case <-time.After(constants.StartupDelay + 5*time.Second):
	}

	for {
		s.checkAndReportHealth()

		select {
		case <-ctx.Done():
			log.Println("[Health] Stopping (shutdown)")
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

	// If cache is empty, wait for syncServices to populate it
	if len(serviceCache) == 0 {
		return
	}

	// Probe services and collect only changed statuses
	var changed []api.ServiceHealthStatus
	for _, svc := range frpServices {
		id, ok := serviceCache[svc.Subdomain]
		if !ok {
			continue
		}

		// Probe the service
		status := "offline"
		host := frp.TranslateLocalhost(svc.LocalIP)
		addr := fmt.Sprintf("%s:%d", host, svc.LocalPort)
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			conn.Close()
			status = "online"
		}

		// Only report if status changed
		s.mu.RLock()
		lastStatus := s.lastHealthStatus[id]
		s.mu.RUnlock()

		if lastStatus != status {
			changed = append(changed, api.ServiceHealthStatus{
				ID:     id,
				Status: status,
			})
			// Update cache
			s.mu.Lock()
			s.lastHealthStatus[id] = status
			s.mu.Unlock()
		}
	}

	// Only call API if something changed
	if len(changed) > 0 {
		log.Printf("[Health] Status changed for %d service(s), reporting", len(changed))
		if err := currentAPIClient.ReportServiceHealth(currentCfg.ServerID, changed); err != nil {
			log.Printf("[Health] Failed to report: %v", err)
			// Revert cache on failure so we retry next cycle
			s.mu.Lock()
			for _, svc := range changed {
				delete(s.lastHealthStatus, svc.ID)
			}
			s.mu.Unlock()
		}
	}
}

// checkForUpdates periodically checks GitHub Releases for a newer client version.
// Checks once after 30s startup delay, then every 24 hours. Skips dev builds.
func (s *Server) checkForUpdates(ctx context.Context) {
	// Skip for dev builds
	if constants.Version == "dev" || strings.HasPrefix(constants.Version, "dev-") {
		return
	}

	// Don't hit GitHub immediately on startup
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
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if json.NewDecoder(resp.Body).Decode(&release) != nil {
		return
	}

	if release.TagName != "" && release.TagName != constants.Version {
		s.mu.Lock()
		s.latestVersion = release.TagName
		s.mu.Unlock()
		log.Printf("[Update] New version available: %s (current: %s)", release.TagName, constants.Version)
	}
}

// ensureServiceCert ensures a TLS certificate exists for the service
// Returns cert path, key path, and any error
func (s *Server) ensureServiceCert(subdomain string) (certPath, keyPath string, err error) {
	if s.certManager == nil {
		return "", "", nil
	}

	// Validate subdomain before constructing domain (defense in depth)
	// Subdomains are more restrictive than hosts: no dots, colons, or brackets
	if !validation.IsValidHost(subdomain) || strings.ContainsAny(subdomain, ".:[]") {
		return "", "", fmt.Errorf("invalid subdomain: %s", subdomain)
	}

	// Build the full domain
	subdomainHost := os.Getenv("SUBDOMAIN_HOST")
	if subdomainHost == "" {
		subdomainHost = constants.DefaultSubdomainHost
	}
	domain := subdomain + "." + subdomainHost

	// Check if we already have a valid cert
	if s.certManager.CertExists(domain) && !s.certManager.NeedsRenewal(domain) {
		cert, key, err := s.certManager.GetCertPaths(domain)
		if err != nil {
			return "", "", err
		}
		return cert, key, nil
	}

	log.Printf("[E2E TLS] Requesting certificate for %s", domain)

	// Generate a new key
	key, err := s.certManager.GenerateKey()
	if err != nil {
		return "", "", err
	}

	// Create CSR
	csrPEM, err := s.certManager.CreateCSR(key, domain)
	if err != nil {
		return "", "", err
	}

	// Request certificate from API
	certResp, err := s.apiClient.RequestCertificate(subdomain, csrPEM)
	if err != nil {
		return "", "", err
	}

	// Save key and cert
	keyPath, err = s.certManager.SaveKey(key, domain)
	if err != nil {
		return "", "", err
	}

	certPath, err = s.certManager.SaveCert([]byte(certResp.Certificate), domain)
	if err != nil {
		return "", "", err
	}

	log.Printf("[E2E TLS] Certificate saved for %s (expires: %s)", domain, certResp.ExpiresAt)
	return certPath, keyPath, nil
}

// configureServiceTLS sets up E2E TLS on a FRP service if enabled.
func (s *Server) configureServiceTLS(frpSvc *frp.Service, subdomain string) {
	if !s.e2eTLSEnabled || s.certManager == nil {
		return
	}
	certPath, keyPath, err := s.ensureServiceCert(subdomain)
	if err != nil {
		log.Printf("[E2E TLS] Failed to get cert for %s: %v", subdomain, err)
		return
	}
	if certPath != "" && keyPath != "" {
		frpSvc.UseE2ETLS = true
		frpSvc.CertPath = certPath
		frpSvc.KeyPath = keyPath
		log.Printf("[E2E TLS] Configured for %s", subdomain)
	}
}

// syncServices fetches services from API and syncs with local FRP config
func (s *Server) syncServices() {
	s.mu.RLock()
	currentCfg := s.cfg
	client := s.frpClient
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil || client == nil {
		return
	}

	// Fetch services from API
	apiServices, err := currentAPIClient.ListServices(currentCfg.ServerID)
	if err != nil {
		log.Printf("[Sync] Failed to fetch services: %v", err)
		return
	}

	// Update service cache for health checks (subdomain → serviceID)
	s.mu.Lock()
	s.serviceCache = make(map[string]string, len(apiServices))
	for _, svc := range apiServices {
		s.serviceCache[svc.Subdomain] = svc.ID
	}
	s.mu.Unlock()

	// Convert to FRP service format with E2E TLS support
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

	// Sync with FRP client
	added, removed, err := client.SyncServices(frpServices)
	if err != nil {
		log.Printf("[Sync] Failed to sync services: %v", err)
		return
	}

	if len(added) > 0 {
		log.Printf("[Sync] Added services: %v", added)
	}
	if len(removed) > 0 {
		log.Printf("[Sync] Removed services: %v", removed)
	}
}

// handleFRPCrash restarts FRP with exponential backoff.
// Respects shutdown context to avoid restarting during shutdown.
// Uses atomic flag to prevent concurrent restarts from state callback + heartbeat loop.
func (s *Server) handleFRPCrash() {
	if !s.restartInProgress.CompareAndSwap(false, true) {
		log.Println("[FRP Recovery] Restart already in progress, skipping")
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

	// Calculate backoff delay
	delay := s.connManager.CalculateBackoff()
	log.Printf("[FRP Recovery] Waiting %v before restart...", delay)

	// Wait with backoff, but abort if shutting down
	timer := time.NewTimer(delay)
	select {
	case <-timer.C:
	case <-s.shutdownCtx.Done():
		timer.Stop()
		log.Println("[FRP Recovery] Cancelled (shutdown)")
		return
	}

	// Check if we should still try to reconnect
	if s.connManager.State() == connection.StateUnpaired {
		log.Println("[FRP Recovery] Cancelled - client unpaired")
		return
	}

	// Notify API we're offline before reconnecting (revokes sessions while down)
	s.mu.RLock()
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentAPIClient != nil {
		if err := currentAPIClient.MarkOffline(currentCfg.ServerID); err != nil {
			log.Printf("[FRP Recovery] Failed to mark offline: %v", err)
		}
	}

	// Reload services from API before restart to ensure fresh state
	if currentAPIClient != nil {
		services, err := currentAPIClient.ListServices(currentCfg.ServerID)
		if err != nil {
			log.Printf("[FRP Recovery] Failed to reload services: %v", err)
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
			log.Printf("[FRP Recovery] Reloaded %d services from API", len(frpServices))
		}
	}

	// Stop and restart FRP with fresh connection ID (crash = new session)
	client.Stop()
	client.ResetConnectionID()
	if err := client.Start(); err != nil {
		log.Printf("[FRP Recovery] Restart failed: %v", err)
		// Will be retried on next heartbeat cycle
	} else {
		log.Println("[FRP Recovery] Restart successful")
		s.connManager.ResetBackoff()
		client.ResetCrashCount()
		s.connManager.SetState(connection.StateConnected)

		// Clear health cache so next health check re-reports all service statuses.
		// Without this, services stay "offline" in the DB because the cache thinks
		// they were already reported as "online" before the crash.
		s.mu.Lock()
		s.lastHealthStatus = make(map[string]string)
		s.mu.Unlock()
	}
}

func (s *Server) reconnectFRP() error {
	s.mu.RLock()
	client := s.frpClient
	s.mu.RUnlock()

	if client == nil {
		return nil
	}
	client.Stop()
	client.ResetConnectionID() // New session — need fresh connection ID
	if err := client.Start(); err != nil {
		return err
	}

	// Clear health cache so services get re-reported after reconnect
	s.mu.Lock()
	s.lastHealthStatus = make(map[string]string)
	s.mu.Unlock()
	return nil
}

func (s *Server) handleUnpairInternal() {
	// Stop FRP
	s.mu.Lock()
	if s.frpClient != nil {
		s.frpClient.Stop()
		s.frpClient = nil
	}

	// Delete local config
	if err := config.Delete(); err != nil {
		log.Printf("[Unpair] Failed to delete config: %v", err)
	}
	s.cfg = nil
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	log.Println("Client reset. Please re-pair at http://localhost:8082")
}

func (s *Server) startWebUI(ctx context.Context, port int) *http.Server {
	mux := http.NewServeMux()

	// Auth endpoints (accessible without auth)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/auth/set-password", s.handleAuthSetPassword)
	mux.HandleFunc("/api/auth/remove-password", s.handleAuthRemovePassword)

	// Serve static assets (logos, icons)
	mux.HandleFunc("/static/", handleStatic)

	// Serve UI pages
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/pair/start", s.handlePairStart)
	mux.HandleFunc("/api/pair/poll", s.handlePairPoll)
	mux.HandleFunc("/api/pair/cancel", s.handlePairCancel)
	mux.HandleFunc("/api/services/add", s.handleAddService)
	mux.HandleFunc("/api/services/list", s.handleListServices)
	mux.HandleFunc("/api/services/delete", s.handleDeleteService)
	mux.HandleFunc("/api/unpair", s.handleUnpair)

	// Default to localhost for security; override with SEAWISE_BIND_ADDR for Docker containers
	bindAddr := os.Getenv("SEAWISE_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}

	// Wrap all routes with auth middleware
	handler := s.auth.middleware(mux)

	srv := &http.Server{
		Addr:              bindAddr + ":" + strconv.Itoa(port),
		Handler:           handler,
		ReadHeaderTimeout: constants.WebUIReadHeaderTimeout,
		ReadTimeout:       constants.WebUIReadTimeout,
		WriteTimeout:      constants.WebUIWriteTimeout,
		IdleTimeout:       constants.WebUIIdleTimeout,
	}

	log.Printf("Web UI listening on %s:%d", bindAddr, port)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Web UI failed: %v (tunnel continues running)", err)
		}
	}()

	return srv
}

func handleStatic(w http.ResponseWriter, r *http.Request) {
	// Serve embedded static files from templates/ directory
	// URL: /static/seawise-logo.png -> templates/seawise-logo.png
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
	if len(name) > 4 && name[len(name)-4:] == ".png" {
		w.Header().Set("Content-Type", "image/png")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if _, err := w.Write(data); err != nil {
		log.Printf("[Static] Failed to write response for %s: %v", name, err)
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if err := indexTemplate.Execute(w, struct {
		WebAppURL string
	}{
		WebAppURL: config.GetWebURL(),
	}); err != nil {
		log.Printf("[WebUI] Template render error: %v", err)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Get hostname for default server name
	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			hostname = constants.DefaultHostname
		}
	}

	// Lock for reading global state
	s.mu.RLock()
	status := map[string]interface{}{
		"pairing_state":    s.pairingState,
		"pairing_code":     s.pairingCode,
		"default_hostname": hostname,
		"version":          constants.Version,
	}
	if s.latestVersion != "" {
		status["latest_version"] = s.latestVersion
	}

	// Add connection state info
	connStatus := s.connManager.GetStatus()
	status["connection"] = connStatus

	// Add FRP process state
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
	s.mu.RUnlock()

	writeJSON(w, status)
}

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse server name from request
	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w,map[string]string{"error": "Request body too large"})
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

	// Request pairing codes from API (OAuth Device Flow: user_code + device_code)
	result, err := s.apiClient.RequestPairing(req.ServerName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w,map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to request pairing code")})
		return
	}

	s.mu.Lock()
	s.pairingCode = result.UserCode       // Show to user
	s.pairingDeviceCode = result.DeviceCode // Keep secret, use for polling
	s.pairingState = "pending"
	s.mu.Unlock()

	// Start polling for approval in background using device_code
	go s.pollForApproval(result.DeviceCode)

	writeJSON(w,map[string]interface{}{
		"code":       result.UserCode, // Only expose user_code to web UI
		"expires_at": result.ExpiresAt,
	})
}

// pollForApproval polls using device_code (OAuth Device Flow)
func (s *Server) pollForApproval(deviceCode string) {
	ticker := time.NewTicker(constants.PairPollInterval)
	defer ticker.Stop()

	timeout := time.After(constants.WebPairTimeout)

	// Capture API client reference once under lock
	s.mu.RLock()
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	for {
		select {
		case <-s.shutdownCtx.Done():
			log.Println("[Pairing] Poll stopped (shutdown)")
			return
		case <-timeout:
			s.mu.Lock()
			s.pairingState = "none"
			s.pairingCode = ""
			s.pairingDeviceCode = ""
			s.mu.Unlock()
			return
		case <-ticker.C:
			// Check if pairing was cancelled
			s.mu.RLock()
			currentState := s.pairingState
			s.mu.RUnlock()
			if currentState != "pending" {
				log.Println("[Pairing] Poll stopped (cancelled)")
				return
			}

			status, err := currentAPIClient.PollPairingStatus(deviceCode)
			if err != nil {
				continue
			}

			switch status {
			case "approved":
				// Complete pairing using device_code
				result, err := currentAPIClient.CompletePairing(deviceCode)
				if err != nil {
					log.Printf("Failed to complete pairing: %v", err)
					s.mu.Lock()
					s.pairingState = "none"
					s.pairingDeviceCode = ""
					s.mu.Unlock()
					return
				}

				// Save config
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
					log.Printf("[Pairing] Failed to save config: %v", err)
				}

				s.apiClient.SetFRPToken(s.cfg.FRPToken)
				s.pairingState = "paired"
				s.pairingCode = ""
				s.pairingDeviceCode = ""
				serverName := s.cfg.ServerName
				s.mu.Unlock()

				log.Printf("Pairing successful! Server: %s", serverName)

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

	log.Println("[Pairing] Cancelled by user")
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

	writeJSON(w,response)
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
		writeJSON(w,map[string]string{"error": "Not paired yet. Connect to SeaWise first."})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w,map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		Name string `json:"name"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "Invalid request body"})
		return
	}

	// Input validation — same rules as CLI (validation package)
	if !validation.IsValidServiceName(req.Name) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "Invalid service name (must be 1-100 characters)"})
		return
	}
	if !validation.IsValidHost(req.Host) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "Invalid host format (must be a valid hostname or IP)"})
		return
	}
	// Security: Block internal/private IPs to prevent SSRF attacks
	if err := validation.ValidateServiceHost(req.Host); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": err.Error()})
		return
	}
	if !validation.IsValidPort(req.Port) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "Invalid port (must be 1-65535)"})
		return
	}

	// Register with API
	svc, err := currentAPIClient.RegisterService(currentCfg.ServerID, req.Name, req.Host, req.Port)
	if err != nil {
		log.Printf("Failed to register service %s: %v", req.Name, err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w,map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to register service")})
		return
	}

	log.Printf("Registered service: %s (subdomain: %s)", req.Name, svc.Subdomain)

	// Add to FRP tunnel
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
			log.Printf("Warning: Failed to add to FRP tunnel: %v", err)
			tunnelWarning = "Service registered but tunnel update pending. It will sync automatically."
		} else {
			log.Printf("Added to FRP tunnel: %s -> %s", req.Name, svc.Subdomain)
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
	writeJSON(w,response)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "Not paired yet"})
		return
	}

	services, err := currentAPIClient.ListServices(currentCfg.ServerID)
	if err != nil {
		log.Printf("Failed to list services: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w,map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to list services")})
		return
	}

	writeJSON(w,map[string]interface{}{
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
		writeJSON(w,map[string]string{"error": "Not paired yet"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w,map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		ServiceID   string `json:"service_id"`
		ServiceName string `json:"service_name"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "Invalid request body"})
		return
	}

	if req.ServiceID == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w,map[string]string{"error": "service_id is required"})
		return
	}

	// Delete from API
	if err := currentAPIClient.DeleteService(currentCfg.ServerID, req.ServiceID); err != nil {
		log.Printf("Failed to delete service %s: %v", req.ServiceID, err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w,map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to delete service")})
		return
	}

	log.Printf("Deleted service: %s (ID: %s)", req.ServiceName, req.ServiceID)

	// Remove from FRP tunnel
	if client != nil && req.ServiceName != "" {
		if err := client.RemoveService(req.ServiceName); err != nil {
			log.Printf("Warning: Failed to remove from FRP tunnel: %v", err)
		} else {
			log.Printf("Removed from FRP tunnel: %s", req.ServiceName)
		}
	}

	writeJSON(w,map[string]interface{}{
		"success": true,
	})
}

func (s *Server) handleUnpair(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Set state to unpaired first
	s.connManager.SetState(connection.StateUnpaired)

	// Snapshot globals under lock for API call
	s.mu.RLock()
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	// Notify API to delete the server (so it's removed from dashboard)
	if currentCfg != nil {
		if err := currentAPIClient.DeleteServer(currentCfg.ServerID); err != nil {
			log.Printf("Warning: Failed to delete server from API: %v", err)
		} else {
			log.Println("Server removed from dashboard")
		}
	}

	// Clean up
	s.handleUnpairInternal()

	writeJSON(w,map[string]interface{}{
		"success": true,
	})
}
