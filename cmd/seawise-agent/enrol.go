package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/enrol"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

// startEnrolment moves a server paired by a 1.x client to its device key
// and returns its status. Without a keystore the tunnel already waits, so
// enrolment waits too.
func startEnrolment(ctx context.Context, log *slog.Logger, st *store.Store, keys identity.Keystore, call *devicecall.Caller, a *agent.Agent, gate *sync.RWMutex) func() enrol.Status {
	if keys == nil {
		return func() enrol.Status {
			if !st.State().EnrolmentNeeded(st.Secrets()) {
				return enrol.Status{State: enrol.StateNotNeeded}
			}
			return enrol.Status{State: enrol.StateEnrolling, LastError: "device keystore unavailable"}
		}
	}
	e, err := enrol.New(enrol.Config{
		Store: st, Keys: keys, Origin: func() string { return apiURL(st) },
		Caller:   call,
		Logger:   log,
		OnChange: func(ctx context.Context) { _ = a.Reconcile(ctx) },
		Gate:     gate,
	})
	if err != nil {
		log.Error("enrolment off", "error", err)
		return func() enrol.Status {
			return enrol.Status{State: enrol.StateEnrolling, LastError: "enrolment off: " + err.Error()}
		}
	}
	go func() { _ = e.Run(ctx) }()
	return e.Status
}
