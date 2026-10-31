package updatecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// A copy of the floor kept elsewhere survives a lost or corrupt state file.
func TestFloorBackupSurvivesLostState(t *testing.T) {
	dir := stateDir(t)
	var backup Versions
	mods := func(c *Config) {
		c.FloorBackup = func() Versions { return backup }
		c.OnVerified = func(v Versions) error { backup = v; return nil }
	}
	p := newPlatformRepo(t, "E", atE)
	mustCheck(t, p.checker(dir, mods))
	if backup != (Versions{Root: 2, Timestamp: 4, Snapshot: 3, Targets: 3}) {
		t.Fatalf("backup %+v", backup)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.set("D", atE)
	var bad *metadata.ErrBadVersionNumber
	if err := p.checker(dir, mods).Check(context.Background()); !errors.As(err, &bad) {
		t.Fatalf("rollback with a corrupt state file: %v", err)
	}
	_ = os.RemoveAll(dir)
	if err := p.checker(dir, mods).Check(context.Background()); !errors.As(err, &bad) {
		t.Fatalf("rollback with the state folder gone: %v", err)
	}
}

// The backup is written before the state; if it cannot be, the check
// fails and the state is not moved.
func TestFloorBackupFailureFailsTheCheck(t *testing.T) {
	dir := stateDir(t)
	p := newPlatformRepo(t, "E", atE)
	c := p.checker(dir, func(c *Config) {
		c.OnVerified = func(Versions) error { return errors.New("disk full") }
	})
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("check passed without its floor backup")
	}
	if st := c.Status(); st.State == StateOK || c.Fresh(atE) {
		t.Fatalf("status %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Fatal("state written without its floor backup")
	}
}
