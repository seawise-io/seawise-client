package adminui

import (
	"context"
	"errors"
	"net/http"

	"github.com/seawise/client/internal/pair"
)

// Pairing pairs this client with a Seawise.io account.
type Pairing interface {
	Start(ctx context.Context, name string) (pair.Status, error)
	Cancel()
	Status() pair.Status
}

func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Pairing == nil {
		errJSON(w, http.StatusServiceUnavailable, "Pairing is unavailable on this client: the device keystore could not be opened")
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Pairing.Status())
}

func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Pairing == nil {
		errJSON(w, http.StatusServiceUnavailable, "Pairing is unavailable on this client: the device keystore could not be opened")
		return
	}
	var req struct {
		ServerName string `json:"server_name"`
	}
	if err := decodeBody(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	st, err := s.cfg.Pairing.Start(r.Context(), req.ServerName)
	var pe *pair.Error
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, st)
	case errors.Is(err, pair.ErrPaired):
		errJSON(w, http.StatusConflict, "This client is already paired")
	case errors.Is(err, pair.ErrInvalidName):
		errJSON(w, http.StatusBadRequest, "Invalid server name (must be 1-100 characters)")
	case errors.As(err, &pe):
		errJSON(w, http.StatusBadGateway, pe.Text)
	default:
		s.log.Error("start pairing", "error", err)
		errJSON(w, http.StatusInternalServerError, "Could not start pairing")
	}
}

func (s *Server) handlePairCancel(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Pairing == nil {
		errJSON(w, http.StatusServiceUnavailable, "Pairing is unavailable on this client: the device keystore could not be opened")
		return
	}
	s.cfg.Pairing.Cancel()
	writeJSON(w, http.StatusOK, s.cfg.Pairing.Status())
}
