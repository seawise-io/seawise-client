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
	"log"
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

// sanitizeLog strips newlines and control characters to prevent log injection.
func sanitizeLog(s string) string {
	return strings.NewReplacer("\n", "", "\r", "", "\t", " ").Replace(s)
}

// writeJSON encodes data as JSON to the response writer.
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[WebUI] Failed to encode JSON response: %v", err)
	}
}

// writeJSONStatus encodes data as JSON with the given HTTP status code.
func writeJSONStatus(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[WebUI] Failed to encode JSON response: %v", err)
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
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("SeaWise Client %s starting...", constants.Version)

	ctx, cancel := context.WithCancel(context.Background())
	s.shutdownCtx = ctx
	s.cancel = cancel

	apiClient, err := api.New(config.GetAPIURL(nil))
	if err != nil {
		log.Fatalf("Invalid API URL: %v", err)
	}
	s.apiClient = apiClient

	s.connManager = connection.NewManager(connection.DefaultConfig())
	s.connManager.SetCallbacks(
		func(old, newState connection.State) {
			log.Printf("[Main] Connection state changed: %s -> %s", old, newState)
		},
		func() {
			log.Println("[Main] Unpair requested by server")
			s.handleUnpairInternal()
		},
	)

	if config.Exists() {
		var err error
		s.cfg, err = config.Load()
		if err != nil {
			log.Printf("Warning: Failed to load config: %v", err)
			s.pairingState = "none"
			s.connManager.SetState(connection.StateDisconnected)
		} else {
			log.Printf("Already paired as server: %s (ID: %s)", s.cfg.ServerName, s.cfg.ServerID)
			storedClient, apiErr := api.New(s.cfg.APIURL)
			if apiErr != nil {
				log.Printf("Warning: Invalid stored API URL: %v", apiErr)
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

	log.Println("SeaWise Client running")
	log.Printf("Open http://localhost:%d to manage this server", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	cancel()

	httpShutdownCtx, httpShutdownRelease := context.WithTimeout(context.Background(), 5*time.Second)
	defer httpShutdownRelease()
	if err := srv.Shutdown(httpShutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

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
	s.auth.Stop()
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

	log.Printf("[FRP] Connecting to %s:%d (TLS: %v)", sanitizeLog(frpServerAddr), frpServerPort, s.cfg.FRPUseTLS) // #nosec G706

	certStatus, err := s.apiClient.GetCertStatus()
	if err != nil {
		log.Printf("[E2E TLS] Failed to check status: %v", err)
		s.e2eTLSEnabled = false
	} else {
		s.e2eTLSEnabled = certStatus.E2ETLSEnabled
		log.Printf("[E2E TLS] Enabled: %v", s.e2eTLSEnabled)
	}

	if s.e2eTLSEnabled {
		s.certManager = certs.New(paths.DataDir())
		if err := s.certManager.EnsureDir(); err != nil {
			log.Printf("[E2E TLS] Failed to create certs dir: %v", err)
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
		log.Printf("[Main] FRP process state: %s", state)
		if state == frp.ProcessCrashed {
			s.connManager.SetState(connection.StateReconnecting)
			go s.handleFRPCrash()
		}
	})

	log.Println("FRP client initialized, ready to add services")

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

	if err := s.frpClient.Start(); err != nil {
		log.Printf("Failed to start FRP: %v", err)
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
			log.Println("[Heartbeat] Stopping (shutdown)")
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
		log.Println("[Heartbeat] Server requests unpair")
		s.connManager.HeartbeatFailed(true)
		return
	}

	if result.Superseded {
		log.Println("[Heartbeat] Connection superseded by another client")
		s.connManager.HeartbeatFailed(false)
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
		log.Printf("[Heartbeat] Server detected gap of %ds", result.Response.GapSeconds)
	}

	// Handle shard migration
	if result.Response != nil && result.Response.Status == "migrate" && result.Response.MigrateTo != nil {
		migrate := result.Response.MigrateTo
		log.Printf("[Heartbeat] Migration requested → %s:%d (shard %s)",
			migrate.FRPServerAddr, migrate.FRPServerPort, migrate.ShardID)

		s.mu.Lock()
		s.cfg.FRPServerAddr = migrate.FRPServerAddr
		s.cfg.FRPServerPort = migrate.FRPServerPort
		if err := s.cfg.Save(); err != nil {
			log.Printf("[Heartbeat] Failed to save migrated config: %v", err)
		}
		s.mu.Unlock()

		if client != nil {
			if err := client.UpdateServer(migrate.FRPServerAddr, migrate.FRPServerPort); err != nil {
				log.Printf("[Heartbeat] Rejected migration to untrusted server: %v", err)
			} else {
				client.ResetConnectionID()
				if err := client.Restart(); err != nil {
					log.Printf("[Heartbeat] Migration restart failed: %v", err)
				} else {
					log.Printf("[Heartbeat] Migration complete → connected to shard %s", migrate.ShardID)
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
			log.Printf("[Heartbeat] Shard address changed: %s:%d → %s:%d",
				storedAddr, storedPort, shard.FRPServerAddr, shard.FRPServerPort)

			if err := client.UpdateServer(shard.FRPServerAddr, shard.FRPServerPort); err != nil {
				log.Printf("[Heartbeat] Rejected shard update to untrusted server: %v", err)
			} else {
				s.mu.Lock()
				s.cfg.FRPServerAddr = shard.FRPServerAddr
				s.cfg.FRPServerPort = shard.FRPServerPort
				if err := s.cfg.Save(); err != nil {
					log.Printf("[Heartbeat] Failed to save updated config: %v", err)
				}
				s.mu.Unlock()

				client.ResetConnectionID()
				if err := client.Restart(); err != nil {
					log.Printf("[Heartbeat] FRP restart after address update failed: %v", err)
				} else {
					log.Printf("[Heartbeat] FRP reconnected to updated shard address")
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
			log.Println("[Sync] Stopping (shutdown)")
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
		log.Printf("[Health] Status changed for %d service(s), reporting", len(changed))
		if err := currentAPIClient.ReportServiceHealth(currentCfg.ServerID, changed); err != nil {
			log.Printf("[Health] Failed to report: %v", err)
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
		log.Printf("[Update] Failed to parse release info: %v", err)
		return
	}

	if release.TagName != "" && release.TagName != constants.Version {
		s.mu.Lock()
		s.latestVersion = release.TagName
		s.mu.Unlock()
		log.Printf("[Update] New version available: %s (current: %s)", release.TagName, constants.Version)
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

	log.Printf("[E2E TLS] Requesting certificate for %s", sanitizeLog(domain)) // #nosec G706

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

	log.Printf("[E2E TLS] Certificate saved for %s (expires: %s)", sanitizeLog(domain), sanitizeLog(certResp.ExpiresAt)) // #nosec G706
	return certPath, keyPath, nil
}

// configureServiceTLS sets up E2E TLS on a FRP service.
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
		log.Printf("[Sync] Failed to fetch services: %v", err)
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

	delay := s.connManager.CalculateBackoff()
	log.Printf("[FRP Recovery] Waiting %v before restart...", delay)

	timer := time.NewTimer(delay)
	select {
	case <-timer.C:
	case <-s.shutdownCtx.Done():
		timer.Stop()
		log.Println("[FRP Recovery] Cancelled (shutdown)")
		return
	}

	if s.connManager.State() == connection.StateUnpaired {
		log.Println("[FRP Recovery] Cancelled - client unpaired")
		return
	}

	s.mu.RLock()
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentAPIClient != nil {
		if err := currentAPIClient.MarkOffline(currentCfg.ServerID); err != nil {
			log.Printf("[FRP Recovery] Failed to mark offline: %v", err)
		}
	}

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

	_ = client.Stop()
	client.ResetConnectionID()
	if err := client.Start(); err != nil {
		log.Printf("[FRP Recovery] Restart failed: %v", err)
		// Will be retried on next heartbeat cycle
	} else {
		log.Println("[FRP Recovery] Restart successful")
		s.connManager.ResetBackoff()
		client.ResetCrashCount()
		s.connManager.SetState(connection.StateConnected)

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
	_ = client.Stop()
	client.ResetConnectionID()
	if err := client.Start(); err != nil {
		return err
	}

	s.mu.Lock()
	s.lastHealthStatus = make(map[string]string)
	s.mu.Unlock()
	return nil
}

func (s *Server) handleUnpairInternal() {
	s.mu.Lock()
	if s.frpClient != nil {
		_ = s.frpClient.Stop()
		s.frpClient = nil
	}

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

	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/auth/set-password", s.handleAuthSetPassword)
	mux.HandleFunc("/api/auth/remove-password", s.handleAuthRemovePassword)

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

	if bindAddr != "127.0.0.1" && bindAddr != "localhost" && bindAddr != "::1" {
		s.auth.networkExposed = true
	}

	if (bindAddr == "0.0.0.0" || bindAddr == "::") && !s.auth.hasPassword() {
		log.Println("[WARNING] ========================================")
		log.Println("[WARNING] Web UI is listening on ALL interfaces")
		log.Println("[WARNING] with NO PASSWORD set. Anyone on your")
		log.Println("[WARNING] network can access and control this client.")
		log.Println("[WARNING] Set a password via the web UI or API:")
		log.Printf("[WARNING]   curl -X POST http://localhost:%d/api/auth/set-password -H 'Content-Type: application/json' -d '{\"password\":\"...\"}'", port)
		log.Println("[WARNING] ========================================")
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
			log.Println("Generating self-signed TLS certificate...")
			if err := generateSelfSignedCert(certFile, keyFile); err != nil {
				log.Printf("[WARNING] Failed to generate TLS cert: %v — falling back to HTTP", err)
				tlsMode = ""
			}
		}

		if tlsMode == "auto" {
			log.Printf("Web UI listening on https://%s:%d (self-signed TLS)", sanitizeLog(bindAddr), port)
			go func() {
				if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
					log.Printf("[ERROR] Web UI TLS failed: %v (tunnel continues running)", err)
				}
			}()
			return srv
		}
	}

	log.Printf("Web UI listening on %s:%d", sanitizeLog(bindAddr), port)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Web UI failed: %v (tunnel continues running)", err)
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
	if len(name) > 4 && name[len(name)-4:] == ".png" {
		w.Header().Set("Content-Type", "image/png")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if _, err := w.Write(data); err != nil { // #nosec G705
		log.Printf("[Static] Failed to write response: %v", err)
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	data := struct {
		WebAppURL    string
		PairingState string
		ServerName   string
		UserEmail    string
		ServerID     string
		Version      string
	}{
		WebAppURL:    config.GetWebURL(),
		PairingState: s.pairingState,
		Version:      constants.Version,
	}
	if s.cfg != nil {
		data.ServerName = s.cfg.ServerName
		data.UserEmail = s.cfg.UserEmail
		data.ServerID = s.cfg.ServerID
	}
	s.mu.RUnlock()

	if err := indexTemplate.Execute(w, data); err != nil {
		log.Printf("[WebUI] Template render error: %v", err)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
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
		"pairing_code":     s.pairingCode,
		"default_hostname": hostname,
		"version":          constants.Version,
	}
	if s.latestVersion != "" {
		status["latest_version"] = s.latestVersion
	}

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
			log.Println("[Pairing] Poll stopped (cancelled or shutdown)")
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
				log.Println("[Pairing] Poll stopped (cancelled)")
				return
			}

			status, err := currentAPIClient.PollPairingStatus(deviceCode)
			if err != nil {
				log.Printf("[Pairing] Poll error: %v", err)
				continue
			}

			switch status {
			case "approved":
				result, err := currentAPIClient.CompletePairing(deviceCode)
				if err != nil {
					log.Printf("Failed to complete pairing: %v", err)
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
					log.Printf("[Pairing] CRITICAL: Failed to save config, aborting pairing: %v", err)
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
		log.Printf("Failed to register service %s: %v", sanitizeLog(req.Name), err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to register app")})
		return
	}

	log.Printf("Registered service: %s (subdomain: %s)", sanitizeLog(req.Name), svc.Subdomain)

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
			tunnelWarning = "App registered but tunnel update pending. It will sync automatically."
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
		log.Printf("Failed to list services: %v", err)
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
		log.Printf("Failed to delete service %s: %v", sanitizeLog(req.ServiceID), err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": validation.SanitizeErrorForUI(err, "Failed to delete app")})
		return
	}

	log.Printf("Deleted service: %s (ID: %s)", sanitizeLog(req.ServiceName), sanitizeLog(req.ServiceID))

	if client != nil && req.ServiceName != "" {
		if err := client.RemoveService(req.ServiceName); err != nil {
			log.Printf("Warning: Failed to remove from FRP tunnel: %v", err)
		} else {
			log.Printf("Removed from FRP tunnel: %s", req.ServiceName)
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
			log.Printf("Warning: Failed to delete server from API: %v", err)
		} else {
			log.Println("Server removed from dashboard")
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
