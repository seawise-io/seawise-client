package main

import (
	"context"
	"crypto"
	"log/slog"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/devapi"
	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/enrol"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

// testAppSyncConfig lets the budget tests shorten the list period; it does
// nothing in release builds.
var testAppSyncConfig = func(*appsync.Config) {}

// startAppSync runs the v2 app sync while a device key exists for a server
// with a v2 identity. Its calls ride the tunnel session while one is up and
// HTTPS otherwise. It returns its status, whether it is active, and the
// engine for local app changes (nil without a keystore or when the outbox
// cannot be read).
func startAppSync(ctx context.Context, log *slog.Logger, st *store.Store, keys identity.Keystore, call *devicecall.Caller, a *agent.Agent) (func() appsync.Status, func() bool, *appsync.Engine) {
	if keys == nil {
		return func() appsync.Status {
			return appsync.Status{Mode: appsync.ModeOff, LastError: "app sync off: no device keystore"}
		}, func() bool { return false }, nil
	}
	signer := func() crypto.Signer {
		k, err := keys.Current()
		if err != nil {
			return nil
		}
		return k
	}
	active := func() bool {
		acc := st.State().Account
		return acc != nil && claims.ValidUUID(acc.ServerID) && enrol.Ready(st.State(), st.Secrets()) && signer() != nil
	}
	carrier, err := devapi.New(devapi.Config{Caller: call, Origin: func() string { return apiURL(st) }, Key: signer, Stream0: a, Logger: log})
	if err != nil {
		log.Error("app sync off", "error", err)
		return func() appsync.Status {
			return appsync.Status{Mode: appsync.ModeOff, LastError: "app sync off: " + err.Error()}
		}, func() bool { return false }, nil
	}
	cfg := appsync.Config{
		Store: st, Carrier: carrier, Logger: log,
		OnChange:   func(ctx context.Context) { _ = a.Reconcile(ctx) },
		OnIdentity: recoverIdentity(log, a),
	}
	testAppSyncConfig(&cfg)
	e, err := appsync.New(cfg)
	if err != nil {
		log.Error("app sync off: the outbox cannot be read", "error", err)
		return func() appsync.Status {
			return appsync.Status{Mode: appsync.ModeOff, LastError: "app sync off: " + err.Error()}
		}, func() bool { return false }, nil
	}
	go func() { _ = e.Run(ctx, active) }()
	return e.Status, func() bool { return active() && e.Listed() }, e
}

// recoverIdentity asks the session manager to prove a pending rotation;
// only its control-key signed proof may commit one.
func recoverIdentity(log *slog.Logger, a *agent.Agent) func(context.Context, string) error {
	return func(ctx context.Context, code string) error {
		if err := a.ProveRotation(ctx); err != nil {
			log.Error("device identity refused by the server", "code", code, "error", err)
			return err
		}
		log.Info("device identity refused; rotation proof requested", "code", code)
		return nil
	}
}
