package tufrepo

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A timestamp rolled back on the host makes the next snapshot version one
// that already exists; it is never overwritten.
func TestVersionedSnapshotNeverOverwritten(t *testing.T) {
	dir, keys := initRefreshed(t)
	root := rootBytes(t, dir)
	oldTS, err := os.ReadFile(filepath.Join(dir, "metadata", "timestamp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignTargets(dir, keys.Targets, map[string][]byte{"keyset.json": []byte(`{"v":1}`)}, nil, t0, DefaultTargetsExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0.Add(time.Hour), DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	snap2 := filepath.Join(dir, "metadata", "2.snapshot.json")
	before, err := os.ReadFile(snap2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata", "timestamp.json"), oldTS, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0.Add(2*time.Hour), DefaultOnlineExpiry, DefaultMinRemaining); err == nil {
		t.Fatal("refresh wrote over an existing snapshot version")
	}
	after, _ := os.ReadFile(snap2)
	if !bytes.Equal(before, after) {
		t.Fatal("2.snapshot.json changed")
	}
}

func TestCreateVersioned(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "1.targets.json")
	if err := createVersioned(p, []byte("a")); err != nil {
		t.Fatal(err)
	}
	// The same bytes again are already in place.
	if err := createVersioned(p, []byte("a")); err != nil {
		t.Fatalf("identical content: %v", err)
	}
	if err := createVersioned(p, []byte("b")); err == nil {
		t.Fatal("different content written over a versioned file")
	}
	if b, _ := os.ReadFile(p); string(b) != "a" {
		t.Fatalf("content %q", b)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files %v", entries)
	}
	// A symlink in place of the file is never followed.
	target := filepath.Join(t.TempDir(), "x")
	link := filepath.Join(dir, "2.targets.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := createVersioned(link, []byte("c")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("symlink target created")
	}
}
