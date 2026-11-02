package main

import (
	"context"
	"log/slog"
	"testing"
)

func TestPairingNeedsAKeystore(t *testing.T) {
	st, ks := importedStore(t)
	call, err := deviceCaller(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := startPairing(context.Background(), slog.Default(), st, nil, call, nil); p != nil {
		t.Fatal("pairing without a keystore")
	}
	p := startPairing(context.Background(), slog.Default(), st, ks, call, nil)
	if p == nil {
		t.Fatal("no pairing with a keystore")
	}
	if s := p.Status(); s.State != "paired" {
		t.Fatalf("imported account shows %+v", s)
	}
}
