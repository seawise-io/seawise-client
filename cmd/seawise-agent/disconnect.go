package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

const (
	pathDisconnect    = "/device/v2/disconnect"
	disconnectTimeout = 15 * time.Second
)

type deviceSender interface {
	Send(ctx context.Context, r devicecall.Request) (devicecall.Answer, error)
}

// disconnector does what the 1.x Disconnect button did: it tells
// Seawise.io, then forgets the account here whatever the answer.
type disconnector struct {
	log  *slog.Logger
	st   *store.Store
	keys identity.Keystore
	call deviceSender
	gate interface {
		RLock()
		RUnlock()
	}
	// legacy is the 1.x call for an account still on its token.
	legacy        func(ctx context.Context, serverID string) error
	legacyAllowed func(store.State) bool
	cancelPairing func()
	reconcile     func(context.Context) error
}

func (d *disconnector) Disconnect(ctx context.Context) (adminui.Disconnected, error) {
	st := d.st.State()
	acc := st.Account
	if acc == nil {
		return adminui.Disconnected{}, adminui.ErrNotPaired
	}
	if d.cancelPairing != nil {
		d.cancelPairing()
	}
	tctx, cancel := context.WithTimeout(ctx, disconnectTimeout)
	told := d.tell(tctx, st)
	cancel()
	if err := d.forget(); err != nil {
		return adminui.Disconnected{}, err
	}
	if d.keys != nil {
		// The next pairing offers a new key; the old one is never used again.
		if _, err := d.keys.Replace(); err != nil {
			d.log.Warn("disconnect: replace device key", "error", err)
		}
	}
	if d.reconcile != nil {
		if err := d.reconcile(ctx); err != nil {
			d.log.Warn("disconnect: stop tunnel", "error", err)
		}
	}
	d.log.Info("disconnected from Seawise.io", "told", told)
	return adminui.Disconnected{Told: told}, nil
}

// tell reports whether Seawise.io no longer lists this server.
func (d *disconnector) tell(ctx context.Context, st store.State) bool {
	acc := st.Account
	if acc.Keyed() {
		if d.keys == nil || d.call == nil {
			return false
		}
		key, err := d.keys.Current()
		if err != nil || key.KeyID() != acc.KeyID {
			return false
		}
		origin, err := devicecall.CheckOrigin(acc.APIURL)
		if err != nil {
			d.log.Warn("disconnect: API origin", "error", err)
			return false
		}
		a, err := d.call.Send(ctx, devicecall.Request{Key: key, Origin: origin, Method: http.MethodPost, Path: pathDisconnect})
		if err != nil {
			d.log.Warn("disconnect: device API", "error", err)
			return false
		}
		if a.Status == http.StatusOK {
			return true
		}
		// A key the server no longer knows belongs to a server it already removed.
		r := devicecall.ParseRefusal(a.Body)
		if a.Status == http.StatusUnauthorized && r.Error == "invalid_proof" && (r.Code == "invalid_proof" || r.Code == "key_revoked") {
			return true
		}
		d.log.Warn("disconnect: device API refused", "status", a.Status, "code", devicecall.SafeCode(r.Code))
		return false
	}
	if d.legacy == nil || d.legacyAllowed == nil || !d.legacyAllowed(st) || d.st.Secrets().FRPToken == "" {
		return false
	}
	if d.gate != nil {
		d.gate.RLock()
		defer d.gate.RUnlock()
	}
	if err := d.legacy(ctx, acc.ServerID); err != nil {
		d.log.Warn("disconnect: control plane", "error", err)
		return false
	}
	return true
}

// forget clears the account, its token and enrolment, and the server's
// ids on each app; the apps themselves stay, as in 1.x.
func (d *disconnector) forget() error {
	err := d.st.Update(func(s *store.State) error {
		s.Account = nil
		s.Enrolment = nil
		for i := range s.Targets {
			s.Targets[i].ServerServiceID = ""
			s.Targets[i].Subdomain = ""
			s.Targets[i].ServerDisableRequestedAt = nil
			s.Targets[i].ServerPublic = false
		}
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	err = d.st.UpdateSecrets(func(s *store.Secrets) error {
		s.FRPToken = ""
		s.Pairing = nil
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	return nil
}
