package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func clock() time.Time { return fixedNow }

func copyV1Fixture(t *testing.T, group string) string {
	t.Helper()
	src := filepath.Join("..", "legacy", "testdata", "v1", group)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			return os.Mkdir(target, 0o700)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// hashV1 records every entry outside v2/.
func hashV1(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == SubDir {
			return filepath.SkipDir
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		v := info.Mode().String() + "|" + info.ModTime().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			v += "|" + hex.EncodeToString(h[:])
		}
		if rel != "." {
			out[rel] = v
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestFirstRunImportPerGroup(t *testing.T) {
	for _, g := range []string{"A", "B", "C", "D", "E"} {
		t.Run("group"+g, func(t *testing.T) {
			dir := copyV1Fixture(t, g)
			before := hashV1(t, dir)

			s, err := Open(dir, clock)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if after := hashV1(t, dir); !equalMaps(before, after) {
				t.Fatalf("v1 files changed:\nbefore %v\nafter  %v", before, after)
			}

			st := s.State()
			if st.UpgradedAt == nil || !st.UpgradedAt.Equal(fixedNow) {
				t.Fatalf("upgraded_at = %v", st.UpgradedAt)
			}
			if st.Account == nil || st.Account.ServerID != "00000000-0000-4000-8000-0000000000a1" || st.Account.APIURL != "https://api.example.invalid" {
				t.Fatalf("account = %+v", st.Account)
			}
			sec := s.Secrets()
			if sec.FRPToken != "synthetic-frp-token-"+g || !strings.HasPrefix(sec.AdminPasswordHash, "$2") {
				t.Fatalf("secrets = %+v", sec)
			}
			if st.Import == nil || len(st.Import.Files) == 0 {
				t.Fatalf("import record = %+v", st.Import)
			}
			for _, tg := range st.Targets {
				if !tg.Grandfathered || tg.ConfirmedAt == nil || !tg.ConfirmedAt.Equal(fixedNow) {
					t.Fatalf("target not grandfathered: %+v", tg)
				}
			}

			bySource := map[string]int{}
			for _, tg := range st.Targets {
				bySource[tg.Source]++
			}
			switch g {
			case "A":
				// no machine.json: everything comes from frpc.toml
				if bySource[SourceV1FRPC] != 3 || bySource[SourceV1Machine] != 0 {
					t.Fatalf("targets = %+v", st.Targets)
				}
				if st.MachineID == "" {
					t.Fatal("machine id not generated")
				}
			case "E":
				// 4 local services; frpc proxies jellyfin and kuma match, nas does not
				if bySource[SourceV1Machine] != 4 || bySource[SourceV1FRPC] != 1 {
					t.Fatalf("targets = %+v", st.Targets)
				}
				if !st.Targets[3].Disabled {
					t.Fatal("disabled flag lost")
				}
			default:
				if bySource[SourceV1Machine] != 3 || bySource[SourceV1FRPC] != 1 {
					t.Fatalf("targets = %+v", st.Targets)
				}
				if st.MachineID != "0123456789abcdef0123456789abcdef" {
					t.Fatalf("machine id = %q", st.MachineID)
				}
			}
		})
	}
}

func TestImportGroupBWithServerManagedApps(t *testing.T) {
	dir := copyV1Fixture(t, "B")
	if err := os.WriteFile(filepath.Join(dir, "machine.json"), []byte(`{"machine_id":"abc","services":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	st := s.State()
	if len(st.Targets) != 3 {
		t.Fatalf("targets = %+v", st.Targets)
	}
	for _, tg := range st.Targets {
		if tg.Source != SourceV1FRPC || !tg.Grandfathered {
			t.Fatalf("target = %+v", tg)
		}
	}
	if st.Targets[2].Name != `nas "ui"` || st.Targets[2].Host != "10.0.0.5" || st.Targets[2].Port != 5000 {
		t.Fatalf("e2e target = %+v", st.Targets[2])
	}
}

func TestFreshInstall(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	st := s.State()
	if st.UpgradedAt != nil || st.Import != nil || st.Account != nil || len(st.Targets) != 0 || st.MachineID == "" {
		t.Fatalf("state = %+v", st)
	}
	if !st.CreatedAt.Equal(fixedNow) {
		t.Fatalf("created_at = %v", st.CreatedAt)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != SubDir {
		t.Fatalf("data dir entries = %v", entries)
	}
}

func TestFilesAndPermissions(t *testing.T) {
	dir := copyV1Fixture(t, "E")
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, SubDir))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("v2 dir mode = %v, %v", info.Mode(), err)
	}
	for _, f := range []string{StateFile, SecretsFile} {
		info, err := os.Stat(filepath.Join(dir, SubDir, f))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, %v", f, info, err)
		}
	}
	state, _ := os.ReadFile(filepath.Join(dir, SubDir, StateFile))
	if strings.Contains(string(state), "synthetic-frp-token") || strings.Contains(string(state), "$2a$") || strings.Contains(string(state), "frp_token") {
		t.Fatal("state.json contains a secret")
	}
	secrets, _ := os.ReadFile(filepath.Join(dir, SubDir, SecretsFile))
	if !strings.Contains(string(secrets), "synthetic-frp-token-E") {
		t.Fatal("secrets.json missing token")
	}
}

func TestReopenDoesNotReimport(t *testing.T) {
	dir := copyV1Fixture(t, "E")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(st *State) error {
		st.Targets = st.Targets[:1]
		st.Targets = append(st.Targets, Target{LocalID: "new", Name: "n", Host: "192.168.1.9", Port: 9, Source: SourceLocal})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return fixedNow.Add(time.Hour) }
	s2, err := Open(dir, later)
	if err != nil {
		t.Fatal(err)
	}
	st := s2.State()
	if len(st.Targets) != 2 || st.Targets[1].LocalID != "new" || st.Targets[1].Grandfathered {
		t.Fatalf("targets = %+v", st.Targets)
	}
	if !st.UpgradedAt.Equal(fixedNow) {
		t.Fatal("upgraded_at changed on reopen")
	}
}

func TestUpdateRejectsInvalidState(t *testing.T) {
	s, err := Open(t.TempDir(), clock)
	if err != nil {
		t.Fatal(err)
	}
	bad := []Target{
		{LocalID: "a", Host: "", Port: 1, Source: SourceLocal},
		{LocalID: "a", Host: "h", Port: 0, Source: SourceLocal},
		{LocalID: "", Host: "h", Port: 1, Source: SourceLocal},
		{LocalID: "a", Host: "h", Port: 1, Source: "server"},
	}
	for i, tg := range bad {
		err := s.Update(func(st *State) error { st.Targets = []Target{tg}; return nil })
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("case %d: err = %v", i, err)
		}
	}
	dup := []Target{{LocalID: "a", Host: "h", Port: 1, Source: SourceLocal}, {LocalID: "a", Host: "h", Port: 2, Source: SourceLocal}}
	if err := s.Update(func(st *State) error { st.Targets = dup; return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("dup: err = %v", err)
	}
	if len(s.State().Targets) != 0 {
		t.Fatal("in-memory state changed after rejected update")
	}
}

func TestStateIsACopy(t *testing.T) {
	dir := copyV1Fixture(t, "E")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	st := s.State()
	st.Targets[0].Host = "mutated"
	st.Account.ServerID = "mutated"
	*st.Targets[0].ConfirmedAt = time.Time{}
	again := s.State()
	if again.Targets[0].Host == "mutated" || again.Account.ServerID == "mutated" || again.Targets[0].ConfirmedAt.IsZero() {
		t.Fatal("State() returned shared memory")
	}
}

func TestSecretsUpdate(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSecrets(func(sec *Secrets) error { sec.FRPToken = "t2"; return nil }); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Secrets().FRPToken != "t2" {
		t.Fatal("secret not persisted")
	}
}

func TestLooseSecretsPermissionsTightened(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, SubDir, SecretsFile)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 || len(s.Warnings) != 1 {
		t.Fatalf("mode %v warnings %v", info.Mode().Perm(), s.Warnings)
	}
}

func TestSymlinkedStoreDirRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, SubDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, clock); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v", err)
	}
}

func TestSymlinkedStateFileRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, SubDir, StateFile)
	b, _ := os.ReadFile(p)
	other := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(other, b, 0o600)
	os.Remove(p)
	if err := os.Symlink(other, p); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, clock); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("err = %v", err)
	}
}

func TestCorruptStateRefused(t *testing.T) {
	for _, body := range []string{`{"schema":1,`, `{}`, `{"schema":"1"}`, `{"schema":1,"machine_id":"m","targets":[]} x`, `{"schema":1,"targets":[]}`} {
		dir := t.TempDir()
		if _, err := Open(dir, clock); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, SubDir, StateFile)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, clock); err == nil {
			t.Fatalf("accepted corrupt state %q", body)
		}
		if b, _ := os.ReadFile(p); string(b) != body {
			t.Fatalf("corrupt state was overwritten for %q", body)
		}
	}
}

func TestV1ImportFailureWritesNothing(t *testing.T) {
	dir := copyV1Fixture(t, "E")
	if err := os.WriteFile(filepath.Join(dir, "account.json"), []byte(`{"server_id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, clock); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(filepath.Join(dir, SubDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("v2 dir created on failed import: %v", err)
	}
}

func TestNewerSchemaRefusedReadOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, SubDir, StateFile)
	body := `{"schema":99,"machine_id":"m","targets":[],"future":true}`
	os.WriteFile(p, []byte(body), 0o600)
	if _, err := Open(dir, clock); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != body {
		t.Fatal("newer state was modified")
	}
}

func withSchema(t *testing.T, version int, ms []func(map[string]any) error) {
	t.Helper()
	oldV, oldM := currentSchema, migrations
	currentSchema, migrations = version, ms
	t.Cleanup(func() { currentSchema, migrations = oldV, oldM })
}

func TestMigrationsRunInOrder(t *testing.T) {
	dir := copyV1Fixture(t, "E")
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	var order []int
	withSchema(t, 3, []func(map[string]any) error{
		func(doc map[string]any) error { order = append(order, 1); doc["machine_name"] = "renamed"; return nil },
		func(doc map[string]any) error {
			order = append(order, 2)
			if doc["machine_name"] != "renamed" {
				t.Error("migration 2 ran before migration 1")
			}
			return nil
		},
	})
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("order = %v", order)
	}
	if s.State().MachineName != "renamed" || s.State().Schema != 3 {
		t.Fatalf("state = %+v", s.State())
	}
	var onDisk map[string]any
	b, _ := os.ReadFile(filepath.Join(dir, SubDir, StateFile))
	json.Unmarshal(b, &onDisk)
	if onDisk["schema"].(float64) != 3 {
		t.Fatalf("schema on disk = %v", onDisk["schema"])
	}
}

func TestFailedMigrationLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, clock); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, SubDir, StateFile)
	before, _ := os.ReadFile(p)
	withSchema(t, 3, []func(map[string]any) error{
		func(doc map[string]any) error { doc["machine_name"] = "half"; return nil },
		func(doc map[string]any) error { return errors.New("boom") },
	})
	if _, err := Open(dir, clock); err == nil {
		t.Fatal("expected error")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("state file changed after failed migration")
	}
}
