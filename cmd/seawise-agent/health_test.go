package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
)

type nopCarrier struct{}

func (nopCarrier) Do(context.Context, appsync.Request) (appsync.Response, error) {
	return appsync.Response{}, context.Canceled
}

func (nopCarrier) Authenticated() bool { return false }

func TestHealthProbeNeedsEngine(t *testing.T) {
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if startHealthProbe(context.Background(), slog.Default(), st, nil, func() bool { return false }, nil) {
		t.Fatal("prober started without an app sync engine")
	}
	e, err := appsync.New(appsync.Config{Store: st, Carrier: nopCarrier{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !startHealthProbe(ctx, slog.Default(), st, nil, func() bool { return false }, e) {
		t.Fatal("prober not started")
	}
}

type upTunnel struct{ up bool }

func (u upTunnel) Run(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
func (u upTunnel) Status() session.Status        { return session.Status{Up: u.up} }

func TestTunnelUpFollowsTheSession(t *testing.T) {
	for _, up := range []bool{true, false} {
		st, err := store.Open(t.TempDir(), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = "synthetic-token"; return nil }); err != nil && !errors.Is(err, store.ErrNotDurable) {
			t.Fatal(err)
		}
		if err := st.Update(func(s *store.State) error {
			s.Account = &store.Account{ServerID: "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b", APIURL: "https://api.example.invalid"}
			return nil
		}); err != nil && !errors.Is(err, store.ErrNotDurable) {
			t.Fatal(err)
		}
		a, err := agent.New(agent.Config{Store: st, Tunnel: func() (agent.Tunnel, error) { return upTunnel{up: up}, nil }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = a.Run(ctx); close(done) }()
		check := tunnelUp(ctx, a)
		got := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if got = check(); got {
				break
			}
			if !up {
				time.Sleep(100 * time.Millisecond)
				got = check()
				break
			}
		}
		if got != up {
			t.Fatalf("tunnel up %v, reported %v", up, got)
		}
		cancel()
		<-done
		if check() {
			t.Fatal("stopped agent reported up")
		}
		st.Close()
	}
}
