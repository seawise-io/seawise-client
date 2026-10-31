package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"

	"github.com/seawise/client/internal/instruction"
	"github.com/seawise/client/internal/keyset"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/updatecheck"
)

// testKeySetConfig lets the memory budget test pin test roots; it does
// nothing in release builds.
var testKeySetConfig = func(*keyset.Config) {}

// trust is the agent's key set: the last verified one for checking signed
// messages, and whether it allows a new session.
type trust struct {
	m *keyset.Manager
}

func (t *trust) current() *protocol.KeySet {
	if t == nil || t.m == nil {
		return nil
	}
	return t.m.Current()
}

func (t *trust) hold() string {
	if t == nil || t.m == nil {
		return keyset.HoldMissing
	}
	return t.m.Hold()
}

func (t *trust) offer(token []byte) {
	if t != nil && t.m != nil {
		_ = t.m.Offer(token)
	}
}

// tufFloor and setTUFFloor keep a copy of the TUF rollback floor in the
// key-set folder.
func (t *trust) tufFloor() updatecheck.Versions {
	if t == nil || t.m == nil {
		return updatecheck.Versions{}
	}
	return updatecheck.Versions(t.m.TUFFloor())
}

func (t *trust) setTUFFloor(v updatecheck.Versions) error {
	if t == nil || t.m == nil {
		return nil
	}
	return t.m.SetTUFFloor(keyset.Floor(v))
}

// accepted is the hash of the accepted key set, for the freshness gate.
func (t *trust) accepted() string {
	if t == nil || t.m == nil {
		return ""
	}
	return t.m.TokenSHA256()
}

func (t *trust) status() any {
	if t == nil || t.m == nil {
		return map[string]string{"hold": keyset.HoldMissing, "error": "no key-set roots in this build"}
	}
	return t.m.Status()
}

func startTrust(log *slog.Logger, st *store.Store) *trust {
	roots, err := keyset.ParseRoots(keyset.Pinned())
	if err != nil {
		log.Error("pinned key-set roots unusable; the tunnel waits", "error", err)
		return &trust{}
	}
	cfg := keyset.Config{Dir: filepath.Join(st.Dir(), "keyset"), Roots: roots, Logger: log}
	testKeySetConfig(&cfg)
	m, err := keyset.New(cfg)
	if errors.Is(err, keyset.ErrNotConfigured) {
		log.Info("no key-set roots in this build; the tunnel waits")
		return &trust{}
	}
	if err != nil {
		log.Error("key set unavailable; the tunnel waits", "error", err)
		return &trust{}
	}
	return &trust{m: m}
}

type instructionExecutors struct {
	unpair    func(context.Context) error
	deleteApp func(context.Context, string) error
}

// executors carry out signed instructions on the local state; both are
// idempotent, and reconcile applies the change to the running tunnel.
func executors(st *store.Store, reconcile func(context.Context) error) instructionExecutors {
	persist := func(err error) error {
		if errors.Is(err, store.ErrNotDurable) {
			return nil
		}
		return err
	}
	return instructionExecutors{
		unpair: func(ctx context.Context) error {
			if err := persist(st.Update(func(s *store.State) error { s.Account = nil; return nil })); err != nil {
				return err
			}
			if err := persist(st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = ""; return nil })); err != nil {
				return err
			}
			return reconcile(ctx)
		},
		deleteApp: func(ctx context.Context, localID string) error {
			err := persist(st.Update(func(s *store.State) error {
				s.Targets = slices.DeleteFunc(s.Targets, func(t store.Target) bool { return t.LocalID == localID })
				return nil
			}))
			if err != nil {
				return err
			}
			return reconcile(ctx)
		},
	}
}

// instructions holds the signed-instruction processor of the paired
// server and rebuilds it when the account changes, with its replay state
// kept per server.
type instructions struct {
	log       *slog.Logger
	st        *store.Store
	t         *trust
	fresh     func(time.Time) bool
	reconcile func(context.Context) error

	mu       sync.Mutex
	p        *instruction.Processor
	serverID string
}

func newInstructions(log *slog.Logger, st *store.Store, t *trust, fresh func(time.Time) bool, reconcile func(context.Context) error) *instructions {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &instructions{log: log, st: st, t: t, fresh: fresh, reconcile: reconcile}
}

// get returns the processor for the server paired now, or nil.
func (h *instructions) get() (*instruction.Processor, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := ""
	if acc := h.st.State().Account; acc != nil && claims.ValidUUID(acc.ServerID) {
		id = acc.ServerID
	}
	if id == h.serverID && (h.p != nil || id == "") {
		return h.p, id
	}
	h.p, h.serverID = nil, id
	if id == "" {
		return nil, ""
	}
	ex := executors(h.st, h.reconcile)
	p, err := instruction.New(instruction.Config{
		Dir: filepath.Join(h.st.Dir(), "instructions", id), ServerID: id,
		KeySet: h.t.current, Fresh: h.fresh, Unpair: ex.unpair, DeleteApp: ex.deleteApp, Logger: h.log,
	})
	if err != nil {
		h.log.Error("signed instructions unavailable", "error", err)
		return nil, id
	}
	h.p = p
	return p, id
}

func (h *instructions) status() any {
	p, id := h.get()
	switch {
	case id == "":
		return map[string]string{"state": "not_paired"}
	case p == nil:
		return map[string]string{"state": "error"}
	}
	return p.Status()
}
