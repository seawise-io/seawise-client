package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/seawise/client/internal/accesslog"
	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/visitor"
)

func streamKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("agent-streams-test/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func streamKeySet(t *testing.T) *protocol.KeySet {
	t.Helper()
	root := streamKey("root")
	pub := streamKey("visitor").Public().(ed25519.PublicKey)
	tok, err := protocol.NewKeySet(root, 1, 1_700_000_000, []protocol.KeySetEntry{{KID: protocol.KeyID(pub), Role: protocol.RoleVisitor,
		X: base64.RawURLEncoding.EncodeToString(pub), Status: protocol.StatusActive}})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// The gate the agent builds reads the signed-time-corrected clock, not the
// system clock.
func TestDataStreamGateUsesSignedClock(t *testing.T) {
	const app = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000a1"
	const signed = int64(1_800_000_000)
	ks := streamKeySet(t)
	tok, err := protocol.NewKeyed(streamKey("visitor"), visitor.TypVisitor, map[string]any{
		"sid": "6d1f3c2a-8b4e-4f7a-9c0d-0000000000c3", "sub": "6d1f3c2a-8b4e-4f7a-9c0d-0000000000d5", "epoch": 0, "aud": app,
		"acct": "6d1f3c2a-8b4e-4f7a-9c0d-0000000000e6", "gen": 1, "av": 1, "iat": signed - 600, "exp": signed + 300})
	if err != nil {
		t.Fatal(err)
	}
	for _, wall := range []int64{signed - 86400, signed + 86400} {
		clock := session.NewSignedClock(func() time.Time { return time.Unix(wall, 0) })
		g, srv, err := newDataStreams(dataStreamSetup{st: pairedStore(t), keySet: func() *protocol.KeySet { return ks }, clock: clock,
			mode:   func() visitor.Mode { return visitor.Enforce },
			dial:   func(context.Context, string) (*forwarder.Upstream, error) { return nil, forwarder.ErrNoApp },
			record: func(accesslog.Entry) {}})
		if err != nil || srv == nil {
			t.Fatal(err)
		}
		r := visitor.Request{AppID: app, Token: tok}
		if d := g.Check(r); d.Allow {
			t.Fatalf("wall %d: allowed before any signed time", wall)
		}
		clock.Observe(signed)
		if d := g.Check(r); !d.Allow || d.Code != visitor.CodeValid {
			t.Fatalf("wall %d: %+v", wall, d)
		}
	}
}
