package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/store"
)

func importedStore(t *testing.T) (*store.Store, identity.Keystore) {
	t.Helper()
	dir := t.TempDir()
	acc := `{"server_id":"6f1d2c3b-4a59-4687-9a1b-2c3d4e5f6a7b","frp_token":"` + strings.Repeat("ab", 32) + `","api_url":"https://api.seawise.io"}`
	if err := os.WriteFile(filepath.Join(dir, "account.json"), []byte(acc), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ks, err := identity.OpenFile(st.Dir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ks.Close() })
	return st, ks
}

// No session starts with a key the server has not enrolled.
func TestTunnelWaitsForEnrolment(t *testing.T) {
	st, ks := importedStore(t)
	k, err := ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	f := tunnelFactory(tunnelSetup{st: st, keys: ks, keySet: func() *protocol.KeySet { return nil }, keySetHold: func() string { return "" }})
	if _, err := f(); !errors.Is(err, agent.ErrNotReady) || !strings.Contains(err.Error(), "enrolling") {
		t.Fatalf("tunnel before enrolment: %v", err)
	}
	if err := st.Update(func(s *store.State) error {
		s.Enrolment = &store.Enrolment{ServerID: s.Account.ServerID, Phase: store.PhaseEnrolled, KeyID: k.KeyID(), StartedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f(); !errors.Is(err, agent.ErrNotReady) || strings.Contains(err.Error(), "enrolling") {
		t.Fatalf("tunnel after enrolment still waits for it: %v", err)
	}
}
