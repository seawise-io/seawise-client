package adminui

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/seawise/client/internal/accesslog"
)

// AccessLog is the reader behind the access log page.
type AccessLog interface {
	Page(cursor string, limit int) (accesslog.Page, error)
}

type accessRow struct {
	accesslog.Entry
	Name string `json:"name"`
}

func (s *Server) handleAccessLog(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AccessLog == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "access log unavailable"})
		return
	}
	q := r.URL.Query()
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit"})
			return
		}
		limit = n
	}
	page, err := s.cfg.AccessLog.Page(q.Get("cursor"), limit)
	if errors.Is(err, accesslog.ErrCursor) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cursor"})
		return
	}
	if err != nil {
		s.log.Error("access log", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read the access log"})
		return
	}
	names := map[string]string{}
	for _, t := range s.cfg.Store.State().Targets {
		names[t.LocalID] = t.Name
	}
	rows := make([]accessRow, 0, len(page.Entries))
	for _, e := range page.Entries {
		rows = append(rows, accessRow{Entry: e, Name: names[e.App]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": rows, "next": page.Next})
}

func (s *Server) handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	if s.cfg.KillSwitch == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "kill switch unavailable"})
		return
	}
	var body struct {
		On *bool `json:"on"`
	}
	if err := decodeBody(r, &body); err != nil || body.On == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if err := s.cfg.KillSwitch(r.Context(), *body.On); err != nil {
		s.log.Error("kill switch", "on", *body.On, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not change the kill switch"})
		return
	}
	s.log.Info("kill switch changed", "on", *body.On)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "on": *body.On})
}

// KillSwitchFunc changes the kill switch.
type KillSwitchFunc func(ctx context.Context, on bool) error
