package updatecheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/seawise/client/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestMetadataFolderMustBePrivate(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	c := f.checker(dir)
	mustCheck(t, c)
	meta := filepath.Join(dir, metaDir)
	if c.readStored("timestamp.json") == nil {
		t.Fatal("stored timestamp not read")
	}
	if err := os.Chmod(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if c.readStored("timestamp.json") != nil {
		t.Fatal("read from a group-readable metadata folder")
	}
	if err := c.Check(context.Background()); err == nil || c.Status().State == StateOK {
		t.Fatal("check stored metadata in a group-readable folder")
	}
	_ = os.Chmod(meta, 0o700)

	// A symlinked metadata folder is not read.
	elsewhere := filepath.Join(t.TempDir(), "m")
	if err := os.Rename(meta, elsewhere); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(filepath.Dir(elsewhere), 0o700)
	if err := os.Symlink(elsewhere, meta); err != nil {
		t.Fatal(err)
	}
	if c.readStored("timestamp.json") != nil {
		t.Fatal("read through a symlinked metadata folder")
	}
}

func TestPersistFailureIsACheckFailure(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := f.checker(dir)
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("check passed without persisting its state")
	}
	if st := c.Status(); st.State == StateOK {
		t.Fatalf("status %+v", st)
	}
}

func TestBadStateKeyFailsClosed(t *testing.T) {
	for name, setup := range map[string]func(string) error{
		"wrong length": func(p string) error { return os.WriteFile(p, []byte("short"), 0o600) },
		"group-readable": func(p string) error {
			if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
				return err
			}
			return os.Chmod(p, 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			dir := stateDir(t)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(dir, "state.key")
			if err := setup(key); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(key)
			c := f.checker(dir)
			if err := c.Check(context.Background()); err == nil || c.Status().State == StateOK {
				t.Fatal("check passed with an unusable state key")
			}
			after, _ := os.ReadFile(key)
			if string(before) != string(after) {
				t.Fatal("state key replaced")
			}
		})
	}
}

func TestRootRotationCap(t *testing.T) {
	for _, n := range []int{maxRootRotations, maxRootRotations + 1} {
		f := newFixture(t)
		for i := 0; i < n; i++ {
			if _, err := tufrepo.RotateRoot(f.repo, tufrepo.RootChange{Signers: f.keys.Root[:2], Now: t0, Expires: tufrepo.DefaultRootExpiry}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tufrepo.Refresh(f.repo, f.root(), f.keys.Snapshot, f.keys.Timestamp, t0, tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
			t.Fatal(err)
		}
		dir := stateDir(t)
		c := f.checker(dir)
		_ = c.Check(context.Background())
		b, err := os.ReadFile(filepath.Join(dir, metaDir, "root.json"))
		if n > maxRootRotations {
			if err == nil {
				r, _ := metadata.Root().FromBytes(b)
				if r.Signed.Version > int64(1+maxRootRotations) {
					t.Fatalf("%d rotations walked", r.Signed.Version-1)
				}
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		r, _ := metadata.Root().FromBytes(b)
		if r.Signed.Version != int64(1+n) {
			t.Fatalf("%d rotations: root v%d", n, r.Signed.Version)
		}
	}
}
