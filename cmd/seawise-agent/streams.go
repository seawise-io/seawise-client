package main

import (
	"context"
	"log/slog"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/streams"
	"github.com/seawise/client/internal/visitor"
)

type dataStreamSetup struct {
	log    *slog.Logger
	st     *store.Store
	keySet func() *protocol.KeySet
	mode   func() visitor.Mode
	clock  *session.SignedClock
	dial   func(ctx context.Context, localID string) (*forwarder.Upstream, error)
	record func(accesslog.Entry)
}

// newDataStreams builds the visitor gate on the signed-time-corrected
// clock and the data-stream handler every session uses.
func newDataStreams(d dataStreamSetup) (*visitor.Gate, *streams.Server, error) {
	g, err := visitor.New(visitor.Config{KeySet: d.keySet, Mode: d.mode, Now: d.clock.Now, Logger: d.log})
	if err != nil {
		return nil, nil, err
	}
	s, err := streams.New(streams.Config{Gate: g, Targets: func() []store.Target { return d.st.State().Targets },
		Dial: d.dial, Record: d.record, ClockReady: d.clock.Ready, Logger: d.log})
	if err != nil {
		return nil, nil, err
	}
	return g, s, nil
}
