package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/connection"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/frp"
	"github.com/seawise/client/internal/validation"
)

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

	slog.Info("Requesting certificate", "component", "e2e_tls", "domain", domain) // #nosec G706

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

	slog.Info("Certificate saved", "component", "e2e_tls", "domain", domain, "expires_at", certResp.ExpiresAt) // #nosec G706
	return certPath, keyPath, nil
}

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

func (s *Server) desiredTunnels(ctx context.Context, apiClient *api.Client, serverID string) ([]frp.Service, error) {
	apiServices, err := apiClient.ListServices(ctx, serverID)
	if err != nil {
		return nil, err
	}
	m, err := config.LoadMachine()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.serviceCache = make(map[string]string, len(apiServices))
	for _, svc := range apiServices {
		s.serviceCache[svc.Subdomain] = svc.ID
	}
	s.mu.Unlock()

	tunnels := buildTunnelServices(m, apiServices)
	for i := range tunnels {
		s.configureServiceTLS(&tunnels[i], tunnels[i].Subdomain)
	}
	return tunnels, nil
}

func (s *Server) syncServices() {
	s.mu.RLock()
	currentCfg := s.cfg
	client := s.frpClient
	currentAPIClient := s.apiClient
	s.mu.RUnlock()

	if currentCfg == nil || client == nil || currentAPIClient == nil {
		return
	}

	tunnels, err := s.desiredTunnels(s.shutdownCtx, currentAPIClient, currentCfg.ServerID)
	if err != nil {
		slog.Error("Failed to fetch services", "component", "sync", "error", err)
		return
	}

	added, removed, err := client.SyncServices(tunnels)
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
		tunnels, err := s.desiredTunnels(s.shutdownCtx, currentAPIClient, currentCfg.ServerID)
		if err != nil {
			slog.Error("Failed to reload services", "component", "frp_recovery", "error", err)
		} else {
			client.SetServices(tunnels)
			slog.Info("Reloaded services", "component", "frp_recovery", "count", len(tunnels))
		}
	}

	_ = client.Stop()
	client.ResetConnectionID()
	if err := client.Start(); err != nil {
		slog.Error("FRP restart failed", "component", "frp_recovery", "error", err)
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
		_ = s.frpClient.Close()
		s.frpClient = nil
	}

	if err := config.DeleteAccount(); err != nil {
		slog.Error("Failed to delete account file", "component", "unpair", "error", err)
	}

	if err := clearServerRegistrations(); err != nil {
		slog.Warn("Failed to clear server IDs on machine state", "component", "unpair", "error", err)
	}

	s.cfg = nil
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	slog.Info("Account disconnected, machine state preserved", "component", "unpair")
}
