package updatecheck

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seawise/client/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A crash after the lowered floor copy was written but before the state
// was: the next check must take the copy's whole floor, not mix the two.
func TestInterruptedRecoveryCompletes(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	var backup Versions
	mods := func(c *Config) {
		c.FloorBackup = func() Versions { return backup }
		c.OnVerified = func(v Versions) error { backup = v; return nil }
	}
	c := f.checker(dir, mods)
	mustCheck(t, c)
	ts, _ := metadata.Timestamp().FromBytes(f.read("timestamp.json"))
	ts.Signed.Version = 1 << 40
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp))
	mustCheck(t, c)
	f.serve("/metadata/timestamp.json", nil)
	newTS, _ := tufrepo.GenerateKey()
	if _, err := tufrepo.RotateRoot(f.repo, tufrepo.RootChange{
		Roles:   map[string]tufrepo.RoleKeys{metadata.TIMESTAMP: {Keys: []ed25519.PublicKey{newTS.Public().(ed25519.PublicKey)}, Threshold: 1}},
		Signers: f.keys.Root[:2], Now: t0, Expires: tufrepo.DefaultRootExpiry,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tufrepo.Refresh(f.repo, f.root(), f.keys.Snapshot, newTS, t0.Add(time.Hour), tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}

	before := filepath.Join(t.TempDir(), "before")
	copyDir(t, dir, before)
	mustCheck(t, c)
	if backup.Root != 2 || backup.Timestamp >= 1<<40 {
		t.Fatalf("backup after recovery %+v", backup)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	copyDir(t, before, dir)

	c2 := f.checker(dir, mods)
	mustCheck(t, c2)
	if fl := c2.saved.Floor; fl.Root != 2 || fl.Timestamp >= 1<<40 {
		t.Fatalf("floor after the interrupted recovery %+v", fl)
	}
	mustCheck(t, f.checker(dir, mods))
}

func TestMergeFloor(t *testing.T) {
	low := Versions{Root: 2, Timestamp: 3, Snapshot: 3, Targets: 2}
	high := Versions{Root: 1, Timestamp: 1 << 40, Snapshot: 1 << 40, Targets: 5}
	if got := mergeFloor(high, low); got != low {
		t.Fatalf("higher root must win whole: %+v", got)
	}
	if got := mergeFloor(low, high); got != low {
		t.Fatalf("higher root must win whole: %+v", got)
	}
	a := Versions{Root: 2, Timestamp: 9, Snapshot: 1, Targets: 4}
	b := Versions{Root: 2, Timestamp: 3, Snapshot: 7, Targets: 4}
	want := Versions{Root: 2, Timestamp: 9, Snapshot: 7, Targets: 4}
	if mergeFloor(a, b) != want || mergeFloor(b, a) != want {
		t.Fatal("equal roots must merge field by field")
	}
}
