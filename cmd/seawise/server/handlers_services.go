package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/connection"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/frp"
	"github.com/seawise/client/internal/validation"
)

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

	if isPaired && currentAPIClient != nil && currentCfg != nil {
		svc, apiErr := currentAPIClient.RegisterService(r.Context(), currentCfg.ServerID, req.Name, req.Host, req.Port)
		if apiErr != nil {
			slog.Warn("Registered locally, but server registration failed", "component", "webui", "service_name", req.Name, "error", apiErr)
			response["warning"] = "Saved locally. Server registration pending, will retry on reconnect."
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

func (s *Server) handleEnableService(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Request body too large"})
		return
	}
	var req struct {
		LocalID string `json:"local_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.LocalID == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "local_id is required"})
		return
	}

	svc, err := setLocalServiceDisabled(req.LocalID, false)
	if err != nil {
		slog.Error("Failed to re-enable service", "component", "webui", "error", err)
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "Failed to re-enable app"})
		return
	}
	if svc == nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "App not found"})
		return
	}

	s.mu.RLock()
	paired := s.pairingState == "paired" && s.cfg != nil
	apiClient := s.apiClient
	var serverID string
	if s.cfg != nil {
		serverID = s.cfg.ServerID
	}
	s.mu.RUnlock()

	if paired && apiClient != nil {
		go func() {
			if err := registerLocalServices(s.shutdownCtx, apiClient, serverID); err != nil {
				slog.Warn("Re-enabled app not registered yet, will retry", "component", "webui", "error", err)
				return
			}
			s.syncServices()
		}()
	}

	slog.Info("Re-enabled service", "component", "webui", "service_name", svc.Name)
	writeJSON(w, map[string]interface{}{"success": true})
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
		if svc.Disabled {
			status = "disabled"
		} else if svc.ServerServiceID != "" {
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
			"id":                svc.ServerServiceID,
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
