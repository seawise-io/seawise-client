package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"

	"github.com/seawise/client/internal/enrol"
	"github.com/seawise/client/internal/store"
)

func TestPairingNeedsAKeystore(t *testing.T) {
	st, ks := importedStore(t)
	call, err := deviceCaller(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := startPairing(context.Background(), slog.Default(), st, nil, call, nil, nil); p != nil {
		t.Fatal("pairing without a keystore")
	}
	p := startPairing(context.Background(), slog.Default(), st, ks, call, nil, nil)
	if p == nil {
		t.Fatal("no pairing with a keystore")
	}
	if s := p.Status(); s.State != "paired" {
		t.Fatalf("imported account shows %+v", s)
	}
}

func TestNeedsReconnect(t *testing.T) {
	st, ks := importedStore(t)
	k, err := ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	none := func() string { return "" }
	held := func(h string) func() enrol.Status { return func() enrol.Status { return enrol.Status{Hold: h} } }
	imported := st.State()
	if needsReconnect(imported, ks, nil, none) || needsReconnect(imported, ks, held(""), none) {
		t.Fatal("imported account with no hold")
	}
	if !needsReconnect(imported, ks, held(store.HoldKeyLost), none) || needsReconnect(imported, ks, held(store.HoldInvalidRequest), none) {
		t.Fatal("enrolment holds")
	}
	enrolled := imported
	enrolled.Enrolment = &store.Enrolment{KeyID: k.KeyID()}
	if needsReconnect(enrolled, ks, nil, none) {
		t.Fatal("enrolment with the current key")
	}
	enrolled.Enrolment = &store.Enrolment{KeyID: strings.Repeat("A", 43)}
	if !needsReconnect(enrolled, ks, nil, none) {
		t.Fatal("enrolment with another key")
	}
	keyed := imported
	keyed.Enrolment = nil
	acc := *imported.Account
	acc.KeyID, acc.DeviceID = k.KeyID(), "d0000000-0000-4000-8000-000000000001"
	keyed.Account = &acc
	if needsReconnect(keyed, ks, held(store.HoldKeyLost), none) {
		t.Fatal("keyed account with its key")
	}
	for _, h := range []string{ladder.HoldRevoked, ladder.HoldRepair} {
		if !needsReconnect(keyed, ks, nil, func() string { return h }) {
			t.Fatalf("tunnel hold %s", h)
		}
	}
	if needsReconnect(keyed, ks, nil, func() string { return ladder.HoldUpdate }) {
		t.Fatal("update hold")
	}
	acc.KeyID = strings.Repeat("B", 43)
	if !needsReconnect(keyed, ks, nil, none) {
		t.Fatal("keyed account with another key")
	}
	if needsReconnect(store.State{}, ks, nil, none) {
		t.Fatal("no account")
	}
	if tunnelHold(context.Background(), nil) != "" {
		t.Fatal("no agent")
	}
}
