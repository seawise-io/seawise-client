package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testServerID = "00000000-0000-4000-8000-0000000000a1"

func TestLoadBackfillsImportServerID(t *testing.T) {
	dir := copyV1Fixture(t, "B")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error { st.Import.ServerID = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.State().Import.ServerID; got != testServerID {
		t.Fatalf("import server id %q", got)
	}
	sdir := s.Dir()
	s.Close()
	b, err := os.ReadFile(filepath.Join(sdir, StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"server_id": "`+testServerID+`"`) && !strings.Contains(string(b), `"server_id":"`+testServerID+`"`) {
		t.Fatalf("backfill not written: %s", b)
	}
}

func TestLoadLeavesImportWithoutAccountOrImport(t *testing.T) {
	dir := copyV1Fixture(t, "B")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error { st.Import.ServerID, st.Account = "", nil; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.State().Import.ServerID; got != "" {
		t.Fatalf("import server id %q without an account", got)
	}
	if err := s.Update(func(st *State) error {
		st.Import = nil
		st.Account = &Account{ServerID: testServerID}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.State().Import != nil {
		t.Fatal("import record created")
	}
}

func TestLoadBackfillNeedsAnImportedAccount(t *testing.T) {
	dir := copyV1Fixture(t, "B")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error { st.Import.ServerID, st.Import.AccountSource = "", ""; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.State().Import.ServerID; got != "" {
		t.Fatalf("import server id %q for an import without an account", got)
	}
}
