package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/session"
)

func (f *fakeTunnel) Relay(_ context.Context, call *pb.DeviceCall) (*pb.DeviceResult, error) {
	return &pb.DeviceResult{CallId: 1, Class: pb.ResultClass_DONE, HttpStatus: 200, Body: call.GetBody()}, nil
}

func TestRelayGoesToTheRunningTunnel(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	h.status()
	r, err := h.agent.Relay(context.Background(), &pb.DeviceCall{Body: []byte("x")})
	if err != nil || string(r.GetBody()) != "x" {
		t.Fatal(r, err)
	}
	if err := h.agent.SetKillSwitch(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.agent.Relay(context.Background(), &pb.DeviceCall{}); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("relayed with the tunnel stopped:", err)
	}
}

func TestRelayWithoutATunnel(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), func(c *Config) {
		c.Tunnel = func() (Tunnel, error) { return nil, fmt.Errorf("%w: no device key yet", ErrNotReady) }
	})
	h.status()
	if _, err := h.agent.Relay(context.Background(), &pb.DeviceCall{}); !errors.Is(err, session.ErrNoSession) {
		t.Fatal(err)
	}
}

func TestRelayClearedWhenTheTunnelStops(t *testing.T) {
	h := newHarness(t, pairedStore(t, t.TempDir()), nil)
	h.status()
	h.stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := h.agent.Relay(context.Background(), &pb.DeviceCall{}); errors.Is(err, session.ErrNoSession) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("relay still set after the agent stopped")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
