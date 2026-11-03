package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"

	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/enrol"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/pair"
	"github.com/seawise/client/internal/store"
)

// startPairing returns the device-key pairing for the admin UI, or nil
// without a keystore. A fresh install pairs only this way; a paired one
// pairs again only once it cannot use its account. A code kept from an
// earlier run is polled again.
func startPairing(ctx context.Context, log *slog.Logger, st *store.Store, keys identity.Keystore, call *devicecall.Caller, a *agent.Agent, enrolment func() enrol.Status) adminui.Pairing {
	if keys == nil {
		return nil
	}
	p, err := pair.New(pair.Config{
		Context: ctx, Store: st, Keys: keys, Caller: call,
		Origin:   func() string { return apiURL(st) },
		WebURL:   envOr("SEAWISE_WEB_URL", constants.DefaultWebURL),
		Logger:   log,
		OnPaired: func(ctx context.Context) { _ = a.Reconcile(ctx) },
		Reconnectable: func() bool {
			return needsReconnect(st.State(), keys, enrolment, func() string { return tunnelHold(ctx, a) })
		},
	})
	if err != nil {
		log.Error("pairing off", "error", err)
		return nil
	}
	p.Resume()
	return p
}

// needsReconnect reports whether the stored account can no longer be used:
// its device key is gone or replaced, the server revoked it, or enrolment
// holds on something only a new pairing clears.
func needsReconnect(st store.State, keys identity.Keystore, enrolment func() enrol.Status, hold func() string) bool {
	acc := st.Account
	if acc == nil {
		return false
	}
	key, err := keys.Current()
	if acc.Keyed() {
		if errors.Is(err, identity.ErrNoKey) || (err == nil && key.KeyID() != acc.KeyID) {
			return true
		}
		h := hold()
		return h == ladder.HoldRevoked || h == ladder.HoldRepair
	}
	if rec := st.Enrolment; rec != nil && rec.KeyID != "" && err == nil && key.KeyID() != rec.KeyID {
		return true
	}
	return enrolment != nil && enrol.NeedsReconnect(enrolment().Hold)
}

// tunnelHold is the session's hold reason, or "" when unknown.
func tunnelHold(ctx context.Context, a *agent.Agent) string {
	if a == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s, err := a.Status(ctx)
	if err != nil || s.Tunnel == nil {
		return ""
	}
	return s.Tunnel.Hold
}

// deviceCaller is the one signer of device API calls outside the tunnel;
// its proofs carry the signed-time clock.
func deviceCaller(clock func() time.Time) (*devicecall.Caller, error) {
	return devicecall.New(devicecall.Config{
		Client:  &http.Client{Transport: controlplane.NewTransport(os.Getenv, nil), Timeout: 30 * time.Second},
		Version: constants.Version, Now: clock,
	})
}
