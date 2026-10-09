package adminui

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

const resolveTimeout = 2 * time.Second

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (s *Server) handleReviewList(w http.ResponseWriter, r *http.Request) {
	items := targetpolicy.BuildReview(r.Context(), s.cfg.Store.State().Targets, s.cfg.Resolver, s.cfg.Gateways())
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleReviewAction confirms or disables one target. A confirmation is
// re-assessed here, so the client cannot grant more than the target needs.
func (s *Server) handleReviewAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LocalID string `json:"local_id"`
		Action  string `json:"action"`
	}
	if err := decodeBody(r, &body); err != nil || body.LocalID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	var target *store.Target
	for _, t := range s.cfg.Store.State().Targets {
		if t.LocalID == body.LocalID {
			t := t
			target = &t
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "app not found"})
		return
	}
	var apply func(*store.State) error
	switch body.Action {
	case "confirm":
		addrs, err := targetpolicy.ResolveHost(r.Context(), s.cfg.Resolver, target.Host)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "host did not resolve"})
			return
		}
		as := targetpolicy.Assess(target.Host, target.Port, addrs, s.cfg.Gateways(), targetpolicy.Options{PublicAllowed: target.Grandfathered || s.cfg.PublicAllowed})
		if as.Refused != "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": as.Refused})
			return
		}
		now := s.cfg.Now()
		apply = func(st *store.State) error { return targetpolicy.Confirm(st, body.LocalID, as, now) }
	case "disable":
		apply = func(st *store.State) error { return targetpolicy.Disable(st, body.LocalID) }
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action"})
		return
	}
	if err := s.cfg.Store.Update(apply); err != nil && !errors.Is(err, store.ErrNotDurable) {
		if errors.Is(err, targetpolicy.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "app not found"})
			return
		}
		s.log.Error("review", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save"})
		return
	}
	s.log.Info("app reviewed", "local_id", body.LocalID, "action", body.Action)
	if s.cfg.OnTargetsChanged != nil {
		s.cfg.OnTargetsChanged(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
