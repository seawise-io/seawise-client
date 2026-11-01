package adminui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/validation"
)

// Apps adds and removes local apps; the app sync tells the server.
type Apps interface {
	Add(name, host string, port int) (string, error)
	Remove(localID string) error
	Kick()
}

type appRow struct {
	LocalID         string `json:"local_id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	IconURL         string `json:"icon_url"`
	ServerServiceID string `json:"server_service_id"`
	Subdomain       string `json:"subdomain"`
	Status          string `json:"status"`
	ID              string `json:"id"`
}

func rowOf(t store.Target) appRow {
	status := "local-only"
	if t.Disabled {
		status = "disabled"
	} else if t.ServerServiceID != "" {
		status = "registered"
	}
	return appRow{LocalID: t.LocalID, Name: t.Name, Host: t.Host, Port: t.Port, IconURL: t.IconURL,
		ServerServiceID: t.ServerServiceID, Subdomain: t.Subdomain, Status: status, ID: t.ServerServiceID}
}

func (s *Server) handleAppList(w http.ResponseWriter, r *http.Request) {
	targets := s.cfg.Store.State().Targets
	rows := make([]appRow, 0, len(targets))
	for _, t := range targets {
		rows = append(rows, rowOf(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": rows})
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleAppAdd checks what 1.x checked, with its messages, then adds the
// app locally; the app sync registers it.
func (s *Server) handleAppAdd(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Apps == nil {
		errJSON(w, http.StatusServiceUnavailable, "App sync is off on this client, so apps cannot be added here")
		return
	}
	var req struct {
		Name string `json:"name"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if !validation.IsValidServiceName(req.Name) {
		errJSON(w, http.StatusBadRequest, "Invalid app name (must be 1-100 characters)")
		return
	}
	if !validation.IsValidHost(req.Host) {
		errJSON(w, http.StatusBadRequest, "Invalid host format (must be a valid hostname or IP)")
		return
	}
	if err := validation.ValidateServiceHost(req.Host); err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validation.IsValidPort(req.Port) {
		errJSON(w, http.StatusBadRequest, "Invalid port (must be 1-65535)")
		return
	}
	id, err := s.cfg.Apps.Add(req.Name, req.Host, req.Port)
	switch {
	case errors.Is(err, appsync.ErrNameExists):
		errJSON(w, http.StatusConflict, "An app with that name already exists")
		return
	case errors.Is(err, appsync.ErrTooManyApps):
		errJSON(w, http.StatusConflict, "Too many apps on this machine")
		return
	case errors.Is(err, appsync.ErrInvalidApp):
		errJSON(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), appsync.ErrInvalidApp.Error()+": "))
		return
	case err != nil:
		s.log.Error("add app", "error", err)
		errJSON(w, http.StatusInternalServerError, "Failed to save app")
		return
	}
	s.log.Info("app added", "local_id", id)
	s.targetsChanged(r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "app": appRow{LocalID: id, Name: req.Name, Host: req.Host, Port: req.Port, Status: "local-only"}})
}

// handleAppDelete removes a local app named by local_id or, as in 1.x, by
// its server id; the app sync deletes it on the server.
func (s *Server) handleAppDelete(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Apps == nil {
		errJSON(w, http.StatusServiceUnavailable, "App sync is off on this client, so apps cannot be deleted here")
		return
	}
	var req struct {
		ServiceID   string `json:"service_id"`
		LocalID     string `json:"local_id"`
		ServiceName string `json:"service_name"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.ServiceID == "" && req.LocalID == "" {
		errJSON(w, http.StatusBadRequest, "service_id or local_id is required")
		return
	}
	id := ""
	for _, t := range s.cfg.Store.State().Targets {
		if (req.LocalID != "" && t.LocalID == req.LocalID) || (req.LocalID == "" && t.ServerServiceID == req.ServiceID) {
			id = t.LocalID
			break
		}
	}
	if id == "" {
		errJSON(w, http.StatusNotFound, "App not found")
		return
	}
	err := s.cfg.Apps.Remove(id)
	switch {
	case errors.Is(err, appsync.ErrNoSuchApp):
		errJSON(w, http.StatusNotFound, "App not found")
		return
	case errors.Is(err, appsync.ErrOutboxFull):
		errJSON(w, http.StatusConflict, "Too many changes waiting for the server; try again after the next sync")
		return
	case err != nil:
		s.log.Error("delete app", "error", err)
		errJSON(w, http.StatusInternalServerError, "Failed to delete app")
		return
	}
	s.log.Info("app deleted", "local_id", id)
	s.targetsChanged(r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) targetsChanged(r *http.Request) {
	if s.cfg.OnTargetsChanged != nil {
		s.cfg.OnTargetsChanged(r.Context())
	}
}
