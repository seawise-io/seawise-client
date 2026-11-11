package updatecheck

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/seawise/client/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// A stolen timestamp key signs a huge version; rotating that key in a new
// root lets agents recover (TUF fast-forward attack recovery).
func TestTimestampFastForwardRecovery(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	c := f.checker(dir)
	mustCheck(t, c)

	ts, err := metadata.Timestamp().FromBytes(f.read("timestamp.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts.Signed.Version = 1 << 40
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp))
	mustCheck(t, c)
	f.serve("/metadata/timestamp.json", nil)
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("timestamp below the fast-forwarded floor accepted before recovery")
	}

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
	mustCheck(t, c)
	// Also after a restart, and the floor applies again from here on.
	c2 := f.checker(dir)
	mustCheck(t, c2)
	if c2.Status().State != StateOK {
		t.Fatalf("%+v", c2.Status())
	}
	old, _ := metadata.Timestamp().FromBytes(f.read("timestamp.json"))
	old.Signed.Version--
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, old, newTS))
	if err := c2.Check(context.Background()); err == nil {
		t.Fatal("rollback accepted after recovery")
	}
}

// Unchanged role keys keep the floor: a root rotation of other keys is no
// reason to forget it.
func TestFloorKeptWhenKeysUnchanged(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	c := f.checker(dir)
	mustCheck(t, c)
	ts, _ := metadata.Timestamp().FromBytes(f.read("timestamp.json"))
	ts.Signed.Version = 1 << 40
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp))
	mustCheck(t, c)
	f.serve("/metadata/timestamp.json", nil)
	newTargets, _ := tufrepo.GenerateKey()
	if _, err := tufrepo.RotateRoot(f.repo, tufrepo.RootChange{
		Roles:   map[string]tufrepo.RoleKeys{metadata.TARGETS: {Keys: []ed25519.PublicKey{newTargets.Public().(ed25519.PublicKey)}, Threshold: 1}},
		Signers: f.keys.Root[:2], Now: t0, Expires: tufrepo.DefaultRootExpiry,
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("timestamp floor reset by a targets key rotation")
	}
}

func TestRoleKeysChanged(t *testing.T) {
	a := &metadata.Role{KeyIDs: []string{"a", "b"}, Threshold: 1}
	for name, c := range map[string]struct {
		b    *metadata.Role
		want bool
	}{
		"same":           {&metadata.Role{KeyIDs: []string{"b", "a"}, Threshold: 1}, false},
		"threshold":      {&metadata.Role{KeyIDs: []string{"a", "b"}, Threshold: 2}, true},
		"key":            {&metadata.Role{KeyIDs: []string{"a", "c"}, Threshold: 1}, true},
		"key removed":    {&metadata.Role{KeyIDs: []string{"a"}, Threshold: 1}, true},
		"missing role":   {nil, true},
		"duplicate keys": {&metadata.Role{KeyIDs: []string{"a", "a"}, Threshold: 1}, true},
	} {
		if got := roleChanged(a, c.b); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if !roleChanged(nil, a) || roleChanged(nil, nil) {
		t.Error("nil roles")
	}
}
