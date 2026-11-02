package main

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/healthprobe"
	"github.com/seawise/client/internal/store"
)

// startHealthProbe feeds app online/offline changes to the app sync engine.
// It reports whether the prober started.
func startHealthProbe(ctx context.Context, log *slog.Logger, st *store.Store, gateways []netip.Addr, connected func() bool, e *appsync.Engine) bool {
	if e == nil {
		return false
	}
	p, err := healthprobe.New(healthprobe.Config{
		Targets:   func() []store.Target { return st.State().Targets },
		Report:    e.SetHealth,
		Connected: connected,
		Gateways:  gateways,
	})
	if err != nil {
		log.Error("app health checks off", "error", err)
		return false
	}
	go p.Run(ctx)
	return true
}

// tunnelUp reports whether the agent has a tunnel session up.
func tunnelUp(ctx context.Context, a *agent.Agent) func() bool {
	return func() bool {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		s, err := a.Status(c)
		return err == nil && s.Connected
	}
}
