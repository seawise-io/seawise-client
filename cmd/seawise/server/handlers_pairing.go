package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/connection"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/validation"
)

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

				if err := registerLocalServices(ctx, currentAPIClient, currentServerID); err != nil {
					slog.Error("Failed to batch-register local services", "component", "pairing", "error", err)
				}

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
	deviceCode := s.pairingDeviceCode
	s.pairingState = "none"
	s.pairingCode = ""
	s.pairingDeviceCode = ""
	s.mu.Unlock()

	if deviceCode != "" && s.apiClient != nil {
		go func(dc string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.apiClient.CancelPairing(ctx, dc); err != nil {
				slog.Warn("Server-side pairing cancel failed", "component", "pairing", "error", err.Error())
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

	response["connection_state"] = string(s.connManager.State())
	s.mu.RUnlock()

	writeJSON(w, response)
}
