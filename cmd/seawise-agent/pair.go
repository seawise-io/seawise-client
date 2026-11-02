package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/pair"
	"github.com/seawise/client/internal/store"
)

// startPairing returns the device-key pairing for the admin UI, or nil
// without a keystore. A fresh install pairs only this way.
func startPairing(ctx context.Context, log *slog.Logger, st *store.Store, keys identity.Keystore, call *devicecall.Caller, a *agent.Agent) adminui.Pairing {
	if keys == nil {
		return nil
	}
	p, err := pair.New(pair.Config{
		Context: ctx, Store: st, Keys: keys, Caller: call,
		Origin:   func() string { return apiURL(st) },
		WebURL:   envOr("SEAWISE_WEB_URL", constants.DefaultWebURL),
		Logger:   log,
		OnPaired: func(ctx context.Context) { _ = a.Reconcile(ctx) },
	})
	if err != nil {
		log.Error("pairing off", "error", err)
		return nil
	}
	return p
}

// deviceCaller is the one signer of device API calls outside the tunnel;
// its proofs carry the signed-time clock.
func deviceCaller(clock func() time.Time) (*devicecall.Caller, error) {
	return devicecall.New(devicecall.Config{
		Client:  &http.Client{Transport: controlplane.NewTransport(os.Getenv, nil), Timeout: 30 * time.Second},
		Version: constants.Version, Now: clock,
	})
}
