package adminui

import (
	"context"
	"errors"
	"net/http"
)

// ErrNotPaired is returned by a Disconnect func when there is no account.
var ErrNotPaired = errors.New("this client is not paired")

// Disconnected reports a disconnect; Told is false when Seawise.io could
// not be reached, so the owner removes the server there.
type Disconnected struct {
	Told bool `json:"told"`
}

// DisconnectFunc unpairs this client: it tells Seawise.io when it can and
// always clears the account on this machine.
type DisconnectFunc func(ctx context.Context) (Disconnected, error)

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Disconnect == nil {
		errJSON(w, http.StatusServiceUnavailable, "Disconnecting is unavailable on this client")
		return
	}
	d, err := s.cfg.Disconnect(r.Context())
	switch {
	case errors.Is(err, ErrNotPaired):
		errJSON(w, http.StatusConflict, "This client is not paired")
	case err != nil:
		s.log.Error("disconnect", "error", err)
		errJSON(w, http.StatusInternalServerError, "Could not disconnect this client")
	default:
		writeJSON(w, http.StatusOK, d)
	}
}
