package updatecheck

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seawise/client/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// recovered runs a fast-forward recovery and one more refresh, and returns
// the timestamp verified before that last refresh.
func recovered(t *testing.T, f *fixture, dir string, mods ...func(*Config)) []byte {
	t.Helper()
	c := f.checker(dir, mods...)
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
	refresh := func(at time.Time) {
		if _, err := tufrepo.Refresh(f.repo, f.root(), f.keys.Snapshot, newTS, at, tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
			t.Fatal(err)
		}
	}
	refresh(t0.Add(time.Hour))
	mustCheck(t, c)
	old := f.read("timestamp.json")
	refresh(t0.Add(2 * time.Hour))
	f.setNow(t0.Add(2 * time.Hour))
	mustCheck(t, c)
	return old
}

// After a recovery, losing the stored root must not let the chain from the
// pinned root reset the floor again.
func TestRecoveryNotReplayedWithoutStoredRoot(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	old := recovered(t, f, dir)
	if err := os.Remove(filepath.Join(dir, metaDir, "root.json")); err != nil {
		t.Fatal(err)
	}
	f.serveBytes("/metadata/timestamp.json", old)
	if err := f.checker(dir).Check(context.Background()); err == nil {
		t.Fatal("older timestamp accepted after the stored root was lost")
	}
}

func TestRecoveryNotReplayedWithoutState(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	var backup Versions
	mods := func(c *Config) {
		c.FloorBackup = func() Versions { return backup }
		c.OnVerified = func(v Versions) error { backup = v; return nil }
	}
	old := recovered(t, f, dir, mods)
	if backup.Root != 2 {
		t.Fatalf("backup %+v", backup)
	}
	if err := os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	f.serveBytes("/metadata/timestamp.json", old)
	if err := f.checker(dir, mods).Check(context.Background()); err == nil {
		t.Fatal("older timestamp accepted after the state was lost")
	}
}
