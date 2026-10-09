package legacy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// Fixtures under testdata/v1 were written by each release's own config,
// auth and frp code with synthetic values.
var groups = []string{"A", "B", "C", "D", "E"}

type entryState struct {
	mode  fs.FileMode
	size  int64
	mtime int64
	sum   string
}

func copyFixture(t *testing.T, group string) string {
	t.Helper()
	src := filepath.Join("testdata", "v1", group)
	dst := t.TempDir()
	if err := os.Chmod(dst, 0o700); err != nil {
		t.Fatal(err)
	}
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

func snapshotTree(t *testing.T, root string) map[string]entryState {
	t.Helper()
	states := map[string]entryState{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := entryState{mode: info.Mode(), size: info.Size(), mtime: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			st.sum = hex.EncodeToString(h[:])
		}
		rel, _ := filepath.Rel(root, p)
		states[rel] = st
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return states
}

func assertTreeUnchanged(t *testing.T, before, after map[string]entryState) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("entry count changed: before %d, after %d (%v)", len(before), len(after), keys(after))
	}
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			t.Fatalf("%s disappeared", name)
		}
		if a != b {
			t.Fatalf("%s changed: before %+v, after %+v", name, b, a)
		}
	}
}

func keys(m map[string]entryState) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestReadLeavesV1FilesUnchanged(t *testing.T) {
	for _, g := range groups {
		t.Run("group"+g, func(t *testing.T) {
			dir := copyFixture(t, g)
			before := snapshotTree(t, dir)
			for i := 0; i < 3; i++ {
				if _, err := Read(dir); err != nil {
					t.Fatalf("Read: %v", err)
				}
			}
			assertTreeUnchanged(t, before, snapshotTree(t, dir))
		})
	}
}

func TestReadWorksOnReadOnlyDataDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not bind root")
	}
	for _, g := range groups {
		t.Run("group"+g, func(t *testing.T) {
			dir := copyFixture(t, g)
			var dirs []string
			_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if d.IsDir() {
					dirs = append(dirs, p)
					return nil
				}
				return os.Chmod(p, 0o400)
			})
			for i := len(dirs) - 1; i >= 0; i-- {
				if err := os.Chmod(dirs[i], 0o500); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				for _, d := range dirs {
					_ = os.Chmod(d, 0o700)
				}
			})
			before := snapshotTree(t, dir)
			if _, err := Read(dir); err != nil {
				t.Fatalf("Read on read-only dir: %v", err)
			}
			assertTreeUnchanged(t, before, snapshotTree(t, dir))
		})
	}
}

func TestReadGroupContents(t *testing.T) {
	for _, g := range groups {
		t.Run("group"+g, func(t *testing.T) {
			snap, err := Read(copyFixture(t, g))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if snap.Account == nil {
				t.Fatal("expected a paired account")
			}
			a := snap.Account
			if a.ServerID != "00000000-0000-4000-8000-0000000000a1" || a.FRPToken != "synthetic-frp-token-"+g {
				t.Fatalf("account = %+v", a)
			}
			if a.APIURL != "https://api.example.invalid" || a.FRPServerAddr != "frp-1.example.invalid" || a.FRPServerPort != 7000 {
				t.Fatalf("account endpoints = %+v", a)
			}
			if len(snap.PasswordHash) != 60 || !strings.HasPrefix(string(snap.PasswordHash), "$2") {
				t.Fatalf("password hash = %q", snap.PasswordHash)
			}
			if snap.FRPC == nil || len(snap.FRPC.Proxies) != 3 {
				t.Fatalf("frpc = %+v, warnings %v", snap.FRPC, snap.Warnings)
			}
			if snap.FRPC.ServerID != a.ServerID {
				t.Fatalf("frpc server id = %q", snap.FRPC.ServerID)
			}
			nas := snap.FRPC.Proxies[2]
			if nas.Name != `nas "ui"` || !nas.E2E || nas.LocalIP != "10.0.0.5" || nas.LocalPort != 5000 || nas.Subdomain != "nas-"+g {
				t.Fatalf("e2e proxy = %+v", nas)
			}
			if p := snap.FRPC.Proxies[1]; p.Name != "kuma" || p.LocalIP != "uptime-kuma" || p.LocalPort != 3001 || p.E2E {
				t.Fatalf("http proxy = %+v", p)
			}

			switch g {
			case "A":
				if snap.Layout != LayoutSingle || snap.AccountSource != "config.json" {
					t.Fatalf("layout %q source %q", snap.Layout, snap.AccountSource)
				}
				if snap.MachineID != "" || len(snap.Services) != 0 {
					t.Fatalf("group A has no machine file: %+v", snap)
				}
				if snap.Account.FRPUseTLS {
					t.Fatal("group A fixture has TLS off")
				}
			default:
				if snap.Layout != LayoutSplit || snap.AccountSource != "account.json" {
					t.Fatalf("layout %q source %q", snap.Layout, snap.AccountSource)
				}
				if snap.MachineID != "0123456789abcdef0123456789abcdef" || snap.MachineName != "nas-"+g {
					t.Fatalf("machine = %q %q", snap.MachineID, snap.MachineName)
				}
				want := 3
				if g == "E" {
					want = 4
				}
				if len(snap.Services) != want {
					t.Fatalf("services = %+v", snap.Services)
				}
				s := snap.Services[0]
				if s.LocalID != "11111111111111111111111111111111" || s.Host != "192.168.1.20" || s.Port != 8096 || s.Subdomain != "jellyfin-"+g || s.ServerServiceID == "" {
					t.Fatalf("service 0 = %+v", s)
				}
				if snap.Services[1].IconURL == "" {
					t.Fatal("icon url lost")
				}
				if g == "E" && !snap.Services[3].Disabled {
					t.Fatal("disabled flag lost")
				}
				for _, s := range snap.Services[:3] {
					if s.Disabled {
						t.Fatalf("unexpected disabled: %+v", s)
					}
				}
			}

			names := map[string]bool{}
			for _, f := range snap.Files {
				names[f.Name] = true
				if len(f.SHA256) != 64 || f.Size <= 0 {
					t.Fatalf("file record %+v", f)
				}
			}
			for _, n := range []string{"tls-cert.pem", "tls-key.pem", "certs"} {
				if names[n] {
					t.Fatalf("%s must not be read", n)
				}
			}
		})
	}
}

func TestReadFileRecordsMatchDisk(t *testing.T) {
	dir := copyFixture(t, "E")
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	disk := snapshotTree(t, dir)
	if len(snap.Files) != 4 {
		t.Fatalf("files = %+v", snap.Files)
	}
	for _, f := range snap.Files {
		if disk[f.Name].sum != f.SHA256 || disk[f.Name].size != f.Size {
			t.Fatalf("record %+v does not match disk %+v", f, disk[f.Name])
		}
	}
}

func TestReadEmptyDir(t *testing.T) {
	snap, err := Read(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Layout != LayoutEmpty || snap.Account != nil || snap.PasswordHash != nil || snap.FRPC != nil {
		t.Fatalf("snap = %+v", snap)
	}
}

func TestReadMissingDir(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadPartialMigrationImportsNoAccount(t *testing.T) {
	dir := copyFixture(t, "B")
	if err := os.Remove(filepath.Join(dir, "account.json")); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join("testdata", "v1", "A", "config.json"), filepath.Join(dir, "config.json"))
	before := snapshotTree(t, dir)
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Layout != LayoutPartial || snap.Account != nil {
		t.Fatalf("layout %q account %+v", snap.Layout, snap.Account)
	}
	if len(snap.Warnings) == 0 {
		t.Fatal("expected a warning")
	}
	if len(snap.Services) != 3 {
		t.Fatalf("services = %d", len(snap.Services))
	}
	assertTreeUnchanged(t, before, snapshotTree(t, dir))
}

func TestReadAccountWinsOverLeftoverConfig(t *testing.T) {
	dir := copyFixture(t, "C")
	copyFile(t, filepath.Join("testdata", "v1", "A", "config.json"), filepath.Join(dir, "config.json"))
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.AccountSource != "account.json" || snap.Account.FRPToken != "synthetic-frp-token-C" {
		t.Fatalf("source %q account %+v", snap.AccountSource, snap.Account)
	}
	for _, f := range snap.Files {
		if f.Name == "config.json" {
			t.Fatal("leftover config.json should not be read")
		}
	}
}

func TestReadAccountWithoutMachine(t *testing.T) {
	dir := copyFixture(t, "D")
	if err := os.Remove(filepath.Join(dir, "machine.json")); err != nil {
		t.Fatal(err)
	}
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Layout != LayoutSplit || snap.Account == nil || len(snap.Services) != 0 {
		t.Fatalf("snap = %+v", snap)
	}
}

func TestReadUnpairedMachineOnly(t *testing.T) {
	dir := copyFixture(t, "E")
	if err := os.Remove(filepath.Join(dir, "account.json")); err != nil {
		t.Fatal(err)
	}
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Layout != LayoutSplit || snap.Account != nil || len(snap.Services) != 4 {
		t.Fatalf("snap = %+v", snap)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadRefusesSymlinks(t *testing.T) {
	for _, name := range []string{"account.json", "machine.json", "password.hash"} {
		t.Run(name, func(t *testing.T) {
			dir := copyFixture(t, "E")
			outside := filepath.Join(t.TempDir(), "target")
			copyFile(t, filepath.Join(dir, name), outside)
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			_, err := Read(dir)
			if !errors.Is(err, ErrNotRegular) {
				t.Fatalf("err = %v, want ErrNotRegular", err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("error should name the file: %v", err)
			}
		})
	}
	t.Run("config.json", func(t *testing.T) {
		dir := copyFixture(t, "A")
		outside := filepath.Join(t.TempDir(), "target")
		copyFile(t, filepath.Join(dir, "config.json"), outside)
		os.Remove(filepath.Join(dir, "config.json"))
		if err := os.Symlink(outside, filepath.Join(dir, "config.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(dir); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestReadSymlinkedFRPCIsAdvisory(t *testing.T) {
	dir := copyFixture(t, "E")
	outside := filepath.Join(t.TempDir(), "frpc.toml")
	copyFile(t, filepath.Join(dir, "frpc.toml"), outside)
	os.Remove(filepath.Join(dir, "frpc.toml"))
	if err := os.Symlink(outside, filepath.Join(dir, "frpc.toml")); err != nil {
		t.Fatal(err)
	}
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.FRPC != nil || len(snap.Warnings) == 0 {
		t.Fatalf("frpc %+v warnings %v", snap.FRPC, snap.Warnings)
	}
}

func TestReadRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := copyFixture(t, "E")
	p := filepath.Join(dir, "account.json")
	os.Remove(p)
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := Read(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadRefusesDirectoryAsFile(t *testing.T) {
	dir := copyFixture(t, "E")
	p := filepath.Join(dir, "machine.json")
	os.Remove(p)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadRefusesHugeFiles(t *testing.T) {
	t.Run("just over the limit", func(t *testing.T) {
		dir := copyFixture(t, "E")
		b := make([]byte, MaxFileSize+1)
		for i := range b {
			b[i] = ' '
		}
		if err := os.WriteFile(filepath.Join(dir, "machine.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(dir); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("sparse 4 GiB", func(t *testing.T) {
		dir := copyFixture(t, "E")
		f, err := os.OpenFile(filepath.Join(dir, "account.json"), os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(4 << 30); err != nil {
			f.Close()
			t.Skipf("truncate: %v", err)
		}
		f.Close()
		if _, err := Read(dir); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oversize frpc.toml is advisory", func(t *testing.T) {
		dir := copyFixture(t, "E")
		if err := os.Truncate(filepath.Join(dir, "frpc.toml"), MaxFileSize+1); err != nil {
			t.Fatal(err)
		}
		snap, err := Read(dir)
		if err != nil {
			t.Fatal(err)
		}
		if snap.FRPC != nil {
			t.Fatal("oversize frpc.toml should be skipped")
		}
	})
}

func TestReadMalformedFilesFailClosed(t *testing.T) {
	cases := []struct {
		name, file, content string
	}{
		{"truncated account", "account.json", `{"server_id": "x", "frp_tok`},
		{"array account", "account.json", `[1,2,3]`},
		{"account without token", "account.json", `{"server_id":"abc"}`},
		{"account without server", "account.json", `{"frp_token":"abc"}`},
		{"truncated machine", "machine.json", `{"machine_id": "abc", "services": [`},
		{"services not array", "machine.json", `{"machine_id": "abc", "services": {}}`},
		{"empty password", "password.hash", ``},
		{"plaintext password", "password.hash", `hunter2`},
		{"trailing garbage", "account.json", `{"server_id":"a","frp_token":"b"} {"x":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t, "E")
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Read(dir)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.file) {
				t.Fatalf("error should name %s: %v", tc.file, err)
			}
		})
	}
}

func TestReadSkipsInvalidServices(t *testing.T) {
	dir := copyFixture(t, "E")
	body := `{"machine_id":"m","services":[
		{"local_id":"a","name":"ok","host":"10.0.0.1","port":80},
		{"local_id":"b","name":"no host","host":"","port":80},
		{"local_id":"c","name":"bad port","host":"10.0.0.1","port":0},
		{"local_id":"d","name":"big port","host":"10.0.0.1","port":70000},
		{"local_id":"a","name":"dup","host":"10.0.0.2","port":81},
		{"local_id":"","name":"no id","host":"10.0.0.3","port":82},
		{"local_id":"e","name":"long host","host":"` + strings.Repeat("h", 300) + `","port":83}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "machine.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Services) != 1 || snap.Services[0].LocalID != "a" || snap.Services[0].Name != "ok" {
		t.Fatalf("services = %+v", snap.Services)
	}
	if len(snap.Warnings) != 6 {
		t.Fatalf("warnings = %v", snap.Warnings)
	}
}

func TestReadTooManyServices(t *testing.T) {
	dir := copyFixture(t, "E")
	var b strings.Builder
	b.WriteString(`{"machine_id":"m","services":[`)
	for i := 0; i <= MaxServices; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"local_id":"x","host":"h","port":1}`)
	}
	b.WriteString("]}")
	if err := os.WriteFile(filepath.Join(dir, "machine.json"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Fatal("expected error")
	}
}

func TestMalformedJSONErrorDoesNotEchoInput(t *testing.T) {
	for _, body := range []string{`{"frp_token":"s3cr3t-value"Q}`, `{"server_id":"a","frp_token":"s3cr3t-value",`, `{"server_id": ["s3cr3t-value"]}`} {
		dir := copyFixture(t, "E")
		if err := os.WriteFile(filepath.Join(dir, "account.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Read(dir)
		if err == nil {
			t.Fatalf("accepted %q", body)
		}
		msg := err.Error()
		if strings.Contains(msg, "s3cr3t") || strings.Contains(msg, "'") || !strings.Contains(msg, "malformed JSON at offset") {
			t.Fatalf("error %q", msg)
		}
	}
}

func TestFRPCErrorDoesNotEchoInput(t *testing.T) {
	_, err := parseFRPC([]byte("[[proxies]]\nname = \"s3cr3t\\q\"\n"))
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), `\q`) {
		t.Fatalf("err = %v", err)
	}
}
