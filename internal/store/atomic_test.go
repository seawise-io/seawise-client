package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var steps = []string{"create", "chmod", "write", "sync", "close", "rename", "dirsync"}

func failAt(t *testing.T, step string) {
	t.Helper()
	old := failpoint
	failpoint = func(s string) error {
		if s == step {
			return errors.New("injected failure at " + s)
		}
		return nil
	}
	t.Cleanup(func() { failpoint = old })
}

func listTemps(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), tmpMarker) {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestWriteFileAtomicFailureAtEachStep(t *testing.T) {
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "f.json")
			if err := WriteFileAtomic(p, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			failAt(t, step)
			err := WriteFileAtomic(p, []byte("new"), 0o600)
			if err == nil {
				t.Fatal("expected injected error")
			}
			got, _ := os.ReadFile(p)
			if step == "dirsync" {
				if !errors.Is(err, ErrNotDurable) || string(got) != "new" {
					t.Fatalf("after rename: err %v content %q", err, got)
				}
			} else if string(got) != "old" {
				t.Fatalf("content = %q, want old", got)
			}
			if temps := listTemps(t, dir); len(temps) != 0 {
				t.Fatalf("temp files left: %v", temps)
			}
		})
	}
}

func TestWriteFileAtomicNewFileFailureLeavesNothing(t *testing.T) {
	for _, step := range steps[:6] {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			failAt(t, step)
			if err := WriteFileAtomic(filepath.Join(dir, "f.json"), []byte("new"), 0o600); err == nil {
				t.Fatal("expected error")
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatalf("entries = %v", entries)
			}
		})
	}
}

func TestWriteFileAtomicPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := WriteFileAtomic(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestStoreUpdateFailureAtEachStep(t *testing.T) {
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			dir := copyV1Fixture(t, "E")
			s, err := Open(dir, clock)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, SubDir, StateFile)
			before, _ := os.ReadFile(p)

			failAt(t, step)
			err = s.Update(func(st *State) error { st.MachineName = "changed"; return nil })
			if err == nil {
				t.Fatal("expected error")
			}
			failpoint = func(string) error { return nil }

			after, _ := os.ReadFile(p)
			if step == "dirsync" {
				if s.State().MachineName != "changed" || string(after) == string(before) {
					t.Fatal("rename happened, memory and disk must both show the change")
				}
			} else if s.State().MachineName == "changed" || string(after) != string(before) {
				t.Fatal("failed update changed memory or disk")
			}

			reopened, err := Open(dir, clock)
			if err != nil {
				t.Fatalf("reopen after failure at %s: %v", step, err)
			}
			if reopened.State().MachineName != s.State().MachineName {
				t.Fatal("disk and memory disagree after reopen")
			}
		})
	}
}

func TestImportCrashBetweenSecretsAndState(t *testing.T) {
	dir := copyV1Fixture(t, "E")
	calls := 0
	old := failpoint
	failpoint = func(s string) error {
		if s == "create" {
			calls++
			if calls == 2 {
				return errors.New("crash before state")
			}
		}
		return nil
	}
	_, err := Open(dir, clock)
	failpoint = old
	if err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(filepath.Join(dir, SubDir, SecretsFile)); err != nil {
		t.Fatalf("secrets should exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, SubDir, StateFile)); err == nil {
		t.Fatal("state must not exist")
	}
	s, err := Open(dir, func() time.Time { return fixedNow.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	if s.Secrets().FRPToken != "synthetic-frp-token-E" || len(s.State().Targets) != 5 {
		t.Fatalf("re-import incomplete: %+v", s.State())
	}
}

func TestStaleTempFilesRemovedOnOpen(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	v2 := filepath.Join(dir, SubDir)
	stale := filepath.Join(v2, "."+StateFile+tmpMarker+"12345")
	if err := os.WriteFile(stale, []byte("{partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(v2, "frpc.toml")
	os.WriteFile(keep, []byte("x"), 0o600)
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("stale temp not removed")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("unrelated file removed")
	}
}
