package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/frp"
)

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
		slog.Warn("Connection superseded, restarting FRP with new connection ID", "component", "heartbeat")
		if client != nil {
			client.ResetConnectionID()
			if err := client.Stop(); err != nil {
				slog.Error("Failed to stop FRP for restart", "component", "heartbeat", "error", err)
			}
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

	if s.reconcileInProgress.CompareAndSwap(false, true) {
		go func() {
			defer s.reconcileInProgress.Store(false)
			changed, err := reconcileMachineServicesWithServer(s.shutdownCtx, currentAPIClient, currentCfg.ServerID)
			if err != nil {
				slog.Warn("Service reconcile failed", "component", "heartbeat", "error", err)
				return
			}
			if changed {
				s.syncServices()
			}
		}()
	}

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
		go func() {
			select {
			case <-time.After(constants.PostReconnectHealthCheckDelay):
			case <-s.shutdownCtx.Done():
				return
			}
			s.checkAndReportHealth()
		}()
	}

	if result.Response != nil && result.Response.Status == "migrate" && result.Response.MigrateTo != nil {
		migrate := result.Response.MigrateTo
		slog.Info("Migration requested", "component", "heartbeat", "addr", migrate.FRPServerAddr, "port", migrate.FRPServerPort, "shard", migrate.ShardID)

		s.mu.RLock()
		cfgGone := s.cfg == nil
		s.mu.RUnlock()
		if cfgGone {
			slog.Info("Migration skipped, unpaired during heartbeat", "component", "heartbeat")
			return
		}
		if client == nil {
			slog.Info("Migration skipped, no active FRP client", "component", "heartbeat")
			return
		}

		if err := client.UpdateServer(migrate.FRPServerAddr, migrate.FRPServerPort); err != nil {
			slog.Warn("Rejected migration to untrusted server", "component", "heartbeat", "error", err)
			return
		}

		s.mu.Lock()
		if s.cfg == nil {
			s.mu.Unlock()
			return
		}
		s.cfg.FRPServerAddr = migrate.FRPServerAddr
		s.cfg.FRPServerPort = migrate.FRPServerPort
		if err := s.cfg.Save(); err != nil {
			slog.Error("Failed to save migrated config", "component", "heartbeat", "error", err)
		}
		s.mu.Unlock()

		client.ResetConnectionID()
		if err := client.Restart(); err != nil {
			slog.Error("Migration restart failed", "component", "heartbeat", "error", err)
		} else {
			slog.Info("Migration complete", "component", "heartbeat", "shard", migrate.ShardID)
			s.mu.Lock()
			s.lastHealthStatus = make(map[string]string)
			s.mu.Unlock()
		}
		return
	}

	if result.Response != nil && result.Response.Shard != nil && client != nil {
		shard := result.Response.Shard
		s.mu.RLock()
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
