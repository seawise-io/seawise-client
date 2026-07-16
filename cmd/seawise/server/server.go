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
	"errors"
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
				// SEA-152: tie the post-reconnect health-check delay to shutdownCtx
				// so a Ctrl-C during reconnect doesn't leave a goroutine running.
				go func() {
					select {
					case <-time.After(constants.PostReconnectHealthCheckDelay):
					case <-s.shutdownCtx.Done():
						return
					}
					s.checkAndReportHealth()
				}()
			}
		},
		func() {
			slog.Info("Unpair requested by server", "component", "main")
			s.handleUnpairInternal()
		},
	)

	if err := config.MigrateLegacy(); err != nil {
		slog.Error("Config migration failed — refusing to start", "component", "main", "error", err)
		os.Exit(1)
	}

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

			// One-time bootstrap: if machine.json has no local services yet
			// but the server does, pull them in so the local machine owns a
			// full picture across future unpair/repair cycles.
			go func() {
				if err := syncMachineServicesFromServer(s.shutdownCtx, s.apiClient, s.cfg.ServerID); err != nil {
					slog.Warn("Initial machine-services sync failed", "component", "main", "error", err)
				}
			}()

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
		// Bounded context so shutdown doesn't hang on a slow API.
		offlineCtx, offlineCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := shutdownAPIClient.MarkOffline(offlineCtx, shutdownCfg.ServerID); err != nil {
			slog.Error("Failed to notify API of shutdown", "component", "main", "error", err)
		} else {
			slog.Info("Notified API: server going offline", "component", "main")
		}
		offlineCancel()
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
	// SEA-152: read config under lock, build state in locals (no s.* mutation
	// during slow API calls or cert setup), then publish to s.* in a single
	// critical section at the end. Keeps the main RWMutex free during network
	// I/O while still satisfying the Go race detector.
	s.mu.RLock()
	cfgSnapshot := s.cfg
	apiClient := s.apiClient
	s.mu.RUnlock()
	if cfgSnapshot == nil || apiClient == nil {
		slog.Error("startServices called before pair config loaded", "component", "main")
		return
	}

	frpServerAddr := cfgSnapshot.FRPServerAddr
	if frpServerAddr == "" {
		frpServerAddr = os.Getenv("FRP_SERVER_ADDR")
	}
	if frpServerAddr == "" {
		frpServerAddr = constants.DockerHostInternal
	}

	frpServerPort := cfgSnapshot.FRPServerPort
	if frpServerPort == 0 {
		frpServerPort = constants.DefaultFRPServerPort
	}

	frpToken := cfgSnapshot.FRPToken

	slog.Info("Connecting to FRP server", "component", "frp", "addr", frpServerAddr, "port", frpServerPort, "tls", cfgSnapshot.FRPUseTLS) // #nosec G706 -- config values, not user input

	var e2eTLSEnabled bool
	var certManager *certs.CertManager

	certStatus, err := apiClient.GetCertStatus(ctx)
	if err != nil {
		slog.Error("Failed to check E2E TLS status", "component", "e2e_tls", "error", err)
	} else {
		e2eTLSEnabled = certStatus.E2ETLSEnabled
		slog.Info("E2E TLS status", "component", "e2e_tls", "enabled", e2eTLSEnabled)
	}

	if e2eTLSEnabled {
		certManager = certs.New(paths.DataDir())
		if err := certManager.EnsureDir(); err != nil {
			slog.Error("Failed to create certs dir", "component", "e2e_tls", "error", err)
			e2eTLSEnabled = false
			certManager = nil
		}
	}

	frpClient := frp.New(frp.Config{
		ServerAddr: frpServerAddr,
		ServerPort: frpServerPort,
		Token:      frpToken,
		ServerID:   cfgSnapshot.ServerID,
		UseTLS:     cfgSnapshot.FRPUseTLS,
	})

	frpClient.SetOnStateChange(func(state frp.ProcessState) {
		slog.Info("FRP process state changed", "component", "main", "state", string(state))
		if state == frp.ProcessCrashed {
			s.connManager.SetState(connection.StateReconnecting)
			go s.handleFRPCrash()
		}
	})

	// Publish FRP client + TLS state under lock. Done before adding services so
	// concurrent readers see a consistent picture (TLS flag matches client).
	s.mu.Lock()
	s.frpClient = frpClient
	s.certManager = certManager
	s.e2eTLSEnabled = e2eTLSEnabled
	s.mu.Unlock()

	slog.Info("FRP client initialized, ready to add services", "component", "frp")

	services, err := s.apiClient.ListServices(ctx, cfgSnapshot.ServerID)
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

	result := currentAPIClient.Heartbeat(s.shutdownCtx, currentCfg.ServerID, frpConnected, serviceCount, constants.Version, connectionID)

	if result.ShouldUnpair {
		s.connManager.UnpairRequested(result.UnpairReason)
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
			// SEA-152: tie the post-supersede restart delay to shutdownCtx.
			go func() {
				select {
				case <-time.After(constants.SupersededRestartDelay):
				case <-s.shutdownCtx.Done():
					return
				}
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
		s.connManager.HeartbeatFailed()
		return
	}

	s.connManager.HeartbeatOK()

	go func() {
		if err := reconcileMachineServicesWithServer(s.shutdownCtx, currentAPIClient, client, currentCfg.ServerID); err != nil {
			slog.Warn("Service reconcile failed", "component", "heartbeat", "error", err)
		}
	}()

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
		// Trigger immediate health check after short delay (network may need a moment).
		// SEA-152: tied to shutdownCtx.
		go func() {
			select {
			case <-time.After(constants.PostReconnectHealthCheckDelay):
			case <-s.shutdownCtx.Done():
				return
			}
			s.checkAndReportHealth()
		}()
	}

	// Handle shard migration
	if result.Response != nil && result.Response.Status == "migrate" && result.Response.MigrateTo != nil {
		migrate := result.Response.MigrateTo
		slog.Info("Migration requested", "component", "heartbeat", "addr", migrate.FRPServerAddr, "port", migrate.FRPServerPort, "shard", migrate.ShardID)

		s.mu.Lock()
		// SEA-164: s.cfg can be nil-ed by handleUnpairInternal between the
		// RLock+snapshot at the top of sendHeartbeat and this Lock — the
		// HTTP round-trip above released the lock. If we got unpaired
		// during the heartbeat, drop the migration: the unpair handler
		// has already torn down state.
		if s.cfg == nil {
			s.mu.Unlock()
			slog.Info("Migration skipped — unpaired during heartbeat", "component", "heartbeat")
			return
		}
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
		// SEA-164: same unpair-race window as the migrate block above.
		if s.cfg == nil {
			s.mu.RUnlock()
			return
		}
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
				// SEA-164: re-check under Lock — UpdateServer above doesn't
				// hold s.mu, so unpair could land between RUnlock and Lock.
				if s.cfg == nil {
					s.mu.Unlock()
					return
				}
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
		// Health-check reaches the local service the same way FRP will —
		// verbatim from the user's config, no transformation. Matches
		// checkLocalIPUsability's rationale in internal/frp/frp.go.
		addr := net.JoinHostPort(svc.LocalIP, fmt.Sprintf("%d", svc.LocalPort))
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
		if err := currentAPIClient.ReportServiceHealth(s.shutdownCtx, currentCfg.ServerID, changed); err != nil {
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
	s.mu.RLock()
	cm := s.certManager
	s.mu.RUnlock()
	if cm == nil {
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

	if cm.CertExists(domain) && !cm.NeedsRenewal(domain) {
		cert, key, err := cm.GetCertPaths(domain)
		if err != nil {
			return "", "", err
		}
		return cert, key, nil
	}

	slog.Info("Requesting certificate", "component", "e2e_tls", "domain", domain) // #nosec G706 -- domain from API config

	key, err := cm.GenerateKey()
	if err != nil {
		return "", "", err
	}

	csrPEM, err := cm.CreateCSR(key, domain)
	if err != nil {
		return "", "", err
	}

	s.mu.RLock()
	apiClient := s.apiClient
	s.mu.RUnlock()
	certResp, err := apiClient.RequestCertificate(subdomain, csrPEM)
	if err != nil {
		return "", "", err
	}

	keyPath, err = cm.SaveKey(key, domain)
	if err != nil {
		return "", "", err
	}

	certPath, err = cm.SaveCert([]byte(certResp.Certificate), domain)
	if err != nil {
		return "", "", err
	}

	slog.Info("Certificate saved", "component", "e2e_tls", "domain", domain, "expires_at", certResp.ExpiresAt) // #nosec G706 -- domain from API config
	return certPath, keyPath, nil
}

// configureServiceTLS sets up E2E TLS on a FRP service.
func (s *Server) configureServiceTLS(frpSvc *frp.Service, subdomain string) {
	s.mu.RLock()
	enabled := s.e2eTLSEnabled
	cm := s.certManager
	s.mu.RUnlock()
	if !enabled || cm == nil {
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

	apiServices, err := currentAPIClient.ListServices(s.shutdownCtx, currentCfg.ServerID)
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
		offlineCtx, offlineCancel := context.WithTimeout(s.shutdownCtx, 10*time.Second)
		if err := currentAPIClient.MarkOffline(offlineCtx, currentCfg.ServerID); err != nil {
			slog.Error("Failed to mark offline", "component", "frp_recovery", "error", err)
		}
		offlineCancel()
	}

	if currentAPIClient != nil {
		services, err := currentAPIClient.ListServices(s.shutdownCtx, currentCfg.ServerID)
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

// handleUnpairInternal drops the current account binding but preserves
// local machine state. Specifically:
//
//   - stops FRP
//   - deletes account.json
//   - clears server_service_id and subdomain on every service in
//     machine.json (those IDs are now stale pointers to nothing)
//   - leaves machine_id, service names, hosts, ports, icons, and
//     password.hash untouched
//
// Callers are expected to have already notified the API (via DELETE
// /servers/:id/disconnect) when the unpair was user-initiated locally —
// this function does not call the API itself, since it is also invoked
// in response to server-initiated unpair signals where the server row
// is already gone.
func (s *Server) handleUnpairInternal() {
	s.mu.Lock()
	if s.frpClient != nil {
		_ = s.frpClient.Stop()
		s.frpClient = nil
	}

	if err := config.DeleteAccount(); err != nil {
		slog.Error("Failed to delete account file", "component", "unpair", "error", err)
	}

	if m, err := config.LoadMachine(); err == nil {
		changed := false
		for i := range m.Services {
			if m.Services[i].ServerServiceID != "" || m.Services[i].Subdomain != "" {
				m.Services[i].ServerServiceID = ""
				m.Services[i].Subdomain = ""
				changed = true
			}
		}
		if changed {
			if err := m.Save(); err != nil {
				slog.Error("Failed to clear stale server IDs on machine state", "component", "unpair", "error", err)
			}
		}
	} else {
		slog.Warn("Machine state not loadable during unpair (nothing to clean)", "component", "unpair", "error", err)
	}

	s.cfg = nil
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	slog.Info("Account disconnected — machine state (services, password) preserved", "component", "unpair")
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

	if !s.auth.hasPassword() && !isLoopbackBindAddr(bindAddr) {
		slog.Warn(
			"First-run wizard active on a non-loopback address — set a password immediately",
			"component", "webui",
			"bind_addr", bindAddr,
			"hint", "Open "+firstRunHintURL(bindAddr, port)+" in a browser to set a password. Until then, only the setup endpoints are reachable.",
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

	result, err := s.apiClient.RequestPairing(r.Context(), req.ServerName)
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

			status, err := currentAPIClient.PollPairingStatus(ctx, deviceCode)
			if err != nil {
				slog.Warn("Pairing poll error", "component", "pairing", "error", err)
				continue
			}

			switch status {
			case "approved":
				result, err := currentAPIClient.CompletePairing(ctx, deviceCode)
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
				currentServerID := s.cfg.ServerID
				currentAPIClient := s.apiClient
				s.mu.Unlock()

				slog.Info("Pairing successful", "component", "pairing", "server_name", serverName)

				// Register any pre-configured local services on the new account.
				// Empty machine.Services is a no-op in the API client.
				if err := registerLocalServices(ctx, currentAPIClient, currentServerID); err != nil {
					slog.Error("Failed to batch-register local services", "component", "pairing", "error", err)
					// Don't fail the pair — services can be synced later, and the
					// machine still has them locally for the next retry.
				}

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

	// Read the device_code under lock, then clear local pairing state.
	// We capture device_code before unlocking so the API call below uses the
	// value we owned at cancel time even if a concurrent re-pair happens.
	s.mu.Lock()
	deviceCode := s.pairingDeviceCode
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	// Tell the server to invalidate the pending code, best-effort. Local
	// cancellation has already succeeded; this prevents a race where the user
	// could approve in their browser tab after we gave up. Fire-and-forget so
	// UX stays instant — if the API is unreachable, the row expires server-side
	// in 15 minutes anyway.
	if deviceCode != "" && s.apiClient != nil {
		go func(dc string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.apiClient.CancelPairing(ctx, dc); err != nil {
				slog.Warn("Server-side pairing cancel failed (will expire on its own)",
					"component", "pairing", "error", err.Error())
			}
		}(deviceCode)
	}

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

	// Step 1: persist locally first. Machine state is the source of truth;
	// the server entry (if any) is derived from it on the next pair.
	local, err := addLocalService(req.Name, req.Host, req.Port, "")
	if err != nil {
		if errors.Is(err, ErrDuplicateServiceName) {
			w.WriteHeader(http.StatusConflict)
			writeJSON(w, map[string]string{"error": "An app with that name already exists"})
			return
		}
		slog.Error("Failed to add service to machine state", "component", "webui", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": "Failed to save app"})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"service": map[string]interface{}{
			"local_id": local.LocalID,
			"name":     local.Name,
			"host":     local.Host,
			"port":     local.Port,
			"status":   "local-only",
		},
	}

	// Step 2: if paired, register with the API and write back the server ID
	// + subdomain. Failures here are soft — the service still exists locally
	// and will be batch-registered on the next pair.
	if isPaired && currentAPIClient != nil && currentCfg != nil {
		svc, apiErr := currentAPIClient.RegisterService(r.Context(), currentCfg.ServerID, req.Name, req.Host, req.Port)
		if apiErr != nil {
			slog.Warn("Registered locally, but server registration failed", "component", "webui", "service_name", req.Name, "error", apiErr)
			response["warning"] = "Saved locally. Server registration pending — will retry on reconnect."
			writeJSON(w, response)
			return
		}

		if err := recordServerRegistration(local.LocalID, svc.ID, svc.Subdomain); err != nil {
			slog.Warn("Failed to record server registration in machine state", "component", "webui", "error", err)
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

		response["service"] = svc
		response["subdomain"] = svc.Subdomain
		if tunnelWarning != "" {
			response["warning"] = tunnelWarning
		}
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, response)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	m, err := config.LoadMachine()
	if err != nil {
		slog.Error("Failed to load machine state", "component", "webui", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": "Failed to load apps"})
		return
	}

	out := make([]map[string]interface{}, 0, len(m.Services))
	for _, svc := range m.Services {
		status := "local-only"
		if svc.ServerServiceID != "" {
			status = "registered"
		}
		out = append(out, map[string]interface{}{
			"local_id":          svc.LocalID,
			"name":              svc.Name,
			"host":              svc.Host,
			"port":              svc.Port,
			"icon_url":          svc.IconURL,
			"server_service_id": svc.ServerServiceID,
			"subdomain":         svc.Subdomain,
			"status":            status,
			// Keep the legacy "id" field pointing at the server ID so the
			// existing UI continues to work for paired clients.
			"id": svc.ServerServiceID,
		})
	}

	writeJSON(w, map[string]interface{}{
		"services": out,
	})
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	s.mu.RLock()
	isPaired := s.pairingState == "paired" && s.cfg != nil
	currentCfg := s.cfg
	currentAPIClient := s.apiClient
	client := s.frpClient
	s.mu.RUnlock()

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		writeJSON(w, map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		ServiceID   string `json:"service_id"`
		LocalID     string `json:"local_id"`
		ServiceName string `json:"service_name"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.ServiceID == "" && req.LocalID == "" {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "service_id or local_id is required"})
		return
	}

	// Remove from machine.json. Try by local_id first, fall back to
	// server id (for older UI clients that still pass it).
	var removed *config.LocalService
	if req.LocalID != "" {
		removed, err = removeLocalServiceByLocalID(req.LocalID)
	} else {
		removed, err = removeLocalServiceByServerID(req.ServiceID)
	}
	if err != nil {
		slog.Error("Failed to remove service from machine state", "component", "webui", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": "Failed to delete app"})
		return
	}
	if removed == nil {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"error": "App not found"})
		return
	}

	// If paired and the service was registered, also delete on the server.
	// Failure here is logged but non-fatal — local state is authoritative,
	// and the orphan on the server will be cleaned up on next disconnect.
	serverServiceID := removed.ServerServiceID
	if req.ServiceID != "" && serverServiceID == "" {
		serverServiceID = req.ServiceID
	}
	if isPaired && currentAPIClient != nil && currentCfg != nil && serverServiceID != "" {
		if err := currentAPIClient.DeleteService(r.Context(), currentCfg.ServerID, serverServiceID); err != nil {
			slog.Warn("Service removed locally, server delete failed", "component", "webui", "service_id", serverServiceID, "error", err)
		}
	}

	slog.Info("Deleted service", "component", "webui", "service_name", removed.Name)

	if client != nil && removed.Name != "" {
		if err := client.RemoveService(removed.Name); err != nil {
			slog.Warn("Failed to remove from FRP tunnel", "component", "webui", "error", err)
		} else {
			slog.Info("Removed from FRP tunnel", "component", "webui", "service_name", removed.Name)
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
		if err := currentAPIClient.DeleteServer(r.Context(), currentCfg.ServerID); err != nil {
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
