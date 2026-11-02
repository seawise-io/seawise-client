package updatecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/seawise/client/internal/store"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// Versions is the highest verified version of each top-level role. It is
// the rollback floor: nothing lower is ever accepted again.
type Versions struct {
	Root      int64 `json:"root"`
	Timestamp int64 `json:"timestamp"`
	Snapshot  int64 `json:"snapshot"`
	Targets   int64 `json:"targets"`
}

type downloader interface {
	DownloadFile(u string, maxLength int64, timeout time.Duration) ([]byte, error)
}

// mergeFloor joins the sealed floor and its copy. The copy is written
// first, so after an interrupted recovery it holds a newer root with lower
// online versions: the floor with the higher root is taken whole, and only
// floors of the same root are merged field by field.
func mergeFloor(a, b Versions) Versions {
	switch {
	case a.Root > b.Root:
		return a
	case b.Root > a.Root:
		return b
	}
	return Versions{Root: a.Root, Timestamp: max(a.Timestamp, b.Timestamp),
		Snapshot: max(a.Snapshot, b.Snapshot), Targets: max(a.Targets, b.Targets)}
}

// verifiedRepo is the outcome of one metadata refresh.
type verifiedRepo struct {
	tm       *trustedmetadata.TrustedMetadata
	versions Versions
	// files are the verified top-level metadata to store.
	files map[string][]byte
}

const metaDir = "metadata"

func (c *Checker) metaPath(name string) string { return filepath.Join(c.cfg.Dir, metaDir, name) }

// readStored reads a stored metadata file; any problem reads as absent.
func (c *Checker) readStored(name string) []byte {
	if err := store.CheckDir(filepath.Join(c.cfg.Dir, metaDir)); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.log.Warn("stored update metadata not used", "error", err)
		}
		return nil
	}
	b, err := store.ReadOwned(c.metaPath(name))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.log.Warn("stored update metadata not used", "file", name, "error", err)
		}
		return nil
	}
	return b
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// startRoot is the stored trusted root when it is the one the sealed state
// recorded and not older than the pinned root; otherwise the pinned root.
func (c *Checker) startRoot(rootSum string) []byte {
	if rootSum == "" {
		return c.cfg.Root
	}
	b := c.readStored("root.json")
	if b == nil || sum(b) != rootSum {
		return c.cfg.Root
	}
	stored, err1 := metadata.Root().FromBytes(b)
	pinned, err2 := metadata.Root().FromBytes(c.cfg.Root)
	if err1 != nil || err2 != nil || stored.Signed.Version < pinned.Signed.Version || (isTestRoot(stored) && !c.cfg.AllowTestRoot) {
		return c.cfg.Root
	}
	return b
}

func rollback(role string, got, floor int64) error {
	return &metadata.ErrBadVersionNumber{Msg: fmt.Sprintf("rollback: %s version %d is below the verified %d", role, got, floor)}
}

// refresh runs the TUF client workflow (root chain, timestamp, snapshot,
// targets) from the stored or pinned root, with the stored metadata and
// the sealed floor as rollback protection.
func (c *Checker) refresh(f downloader, now time.Time, floor Versions, rootSum string) (*verifiedRepo, error) {
	start := c.startRoot(rootSum)
	tm, err := trustedmetadata.New(start)
	if err != nil {
		return nil, err
	}
	tm.RefTime = now
	files := map[string][]byte{}

	// Fast-forward recovery: a root newer than the floor that replaces the
	// keys of an online role starts that role again without its stored
	// copy and floor. Steps at or below the floor were seen before and
	// never reset anything, even when the chain is walked again from the
	// pinned root.
	resetOnline, resetTargets := false, false
	base := tm.Root.Signed.Version
	for v := base + 1; v <= base+maxRootRotations; v++ {
		data, err := f.DownloadFile(fmt.Sprintf("%s%d.root.json", c.metaURL, v), maxRootSize, 0)
		var he *metadata.ErrDownloadHTTP
		if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
			break
		}
		if err != nil {
			return nil, err
		}
		prev := tm.Root
		if _, err := tm.UpdateRoot(data); err != nil {
			return nil, err
		}
		if next := tm.Root; next.Signed.Version > floor.Root {
			changed := func(role string) bool { return roleChanged(prev.Signed.Roles[role], next.Signed.Roles[role]) }
			resetOnline = resetOnline || changed(metadata.TIMESTAMP) || changed(metadata.SNAPSHOT)
			resetTargets = resetTargets || changed(metadata.TARGETS)
		}
		files["root.json"] = data
	}
	if err := checkRootThreshold(tm.Root); err != nil {
		return nil, err
	}
	if isTestRoot(tm.Root) && !c.cfg.AllowTestRoot {
		return nil, ErrTestRoot
	}
	if tm.Root.Signed.Version < floor.Root {
		return nil, rollback("root", tm.Root.Signed.Version, floor.Root)
	}
	skip := map[string]bool{}
	if resetOnline {
		floor.Timestamp, floor.Snapshot = 0, 0
		skip["timestamp.json"], skip["snapshot.json"] = true, true
	}
	if resetTargets {
		floor.Targets = 0
		skip["targets.json"] = true
	}
	stored := func(name string) []byte {
		if skip[name] {
			return nil
		}
		return c.readStored(name)
	}
	if files["root.json"] == nil {
		files["root.json"] = start
	}

	// Stored copies only seed rollback protection; a stale or invalid one
	// is ignored as go-tuf does.
	if b := stored("timestamp.json"); b != nil {
		if _, err := tm.UpdateTimestamp(b); err != nil && !errors.Is(err, &metadata.ErrRepository{}) {
			return nil, err
		}
	}
	data, err := f.DownloadFile(c.metaURL+"timestamp.json", maxTimestampSize, 0)
	if err != nil {
		return nil, err
	}
	if _, err := tm.UpdateTimestamp(data); err != nil {
		if !errors.Is(err, &metadata.ErrEqualVersionNumber{}) {
			return nil, err
		}
	} else {
		files["timestamp.json"] = data
	}
	if tm.Timestamp == nil {
		return nil, &metadata.ErrRepository{Msg: "no trusted timestamp"}
	}
	if tm.Timestamp.Signed.IsExpired(now) {
		return nil, &metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"}
	}

	if b := stored("snapshot.json"); b == nil || func() bool {
		_, err := tm.UpdateSnapshot(b, true)
		return err != nil
	}() {
		sm := tm.Timestamp.Signed.Meta["snapshot.json"]
		if sm == nil {
			return nil, &metadata.ErrRepository{Msg: "timestamp has no snapshot entry"}
		}
		length := sm.Length
		if length <= 0 || length > maxSnapshotSize {
			length = maxSnapshotSize
		}
		data, err := f.DownloadFile(fmt.Sprintf("%s%d.snapshot.json", c.metaURL, sm.Version), length, 0)
		if err != nil {
			return nil, err
		}
		if _, err := tm.UpdateSnapshot(data, false); err != nil {
			return nil, err
		}
		files["snapshot.json"] = data
	}

	tmeta := tm.Snapshot.Signed.Meta["targets.json"]
	if tmeta == nil {
		return nil, &metadata.ErrRepository{Msg: "snapshot has no targets entry"}
	}
	if b := stored("targets.json"); b == nil || func() bool {
		_, err := tm.UpdateTargets(b)
		return err != nil
	}() {
		length := tmeta.Length
		if length <= 0 || length > maxTargetsSize {
			length = maxTargetsSize
		}
		data, err := f.DownloadFile(fmt.Sprintf("%s%d.targets.json", c.metaURL, tmeta.Version), length, 0)
		if err != nil {
			return nil, err
		}
		if _, err := tm.UpdateTargets(data); err != nil {
			return nil, err
		}
		files["targets.json"] = data
	}

	targets := tm.Targets[metadata.TARGETS]
	got := Versions{Root: tm.Root.Signed.Version, Timestamp: tm.Timestamp.Signed.Version, Snapshot: tm.Snapshot.Signed.Version, Targets: targets.Signed.Version}
	for _, r := range []struct {
		role      string
		got, want int64
	}{{"timestamp", got.Timestamp, floor.Timestamp}, {"snapshot", got.Snapshot, floor.Snapshot}, {"targets", got.Targets, floor.Targets}} {
		if r.got < r.want {
			return nil, rollback(r.role, r.got, r.want)
		}
	}
	return &verifiedRepo{tm: tm, versions: got, files: files}, nil
}

// roleChanged reports whether the keys or threshold of a role differ.
func roleChanged(a, b *metadata.Role) bool {
	if a == nil || b == nil {
		return a != b
	}
	if a.Threshold != b.Threshold || len(a.KeyIDs) != len(b.KeyIDs) {
		return true
	}
	x, y := slices.Clone(a.KeyIDs), slices.Clone(b.KeyIDs)
	slices.Sort(x)
	slices.Sort(y)
	return !slices.Equal(x, y) || len(slices.Compact(y)) != len(b.KeyIDs)
}

// fetchTarget downloads a target by its consistent-snapshot name and
// checks its length and hashes.
func (c *Checker) fetchTarget(f downloader, tf *metadata.TargetFiles, max int64) ([]byte, error) {
	if tf.Length <= 0 || tf.Length > max {
		return nil, fmt.Errorf("target %s too large (%d bytes, limit %d)", tf.Path, tf.Length, max)
	}
	h, ok := tf.Hashes["sha256"]
	if !ok || len(h) != sha256.Size {
		return nil, fmt.Errorf("target %s has no sha256 hash", tf.Path)
	}
	dir, name := path.Split(tf.Path)
	data, err := f.DownloadFile(c.targetsURL+dir+hex.EncodeToString(h)+"."+name, tf.Length, 0)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", tf.Path, err)
	}
	if err := tf.VerifyLengthHashes(data); err != nil {
		return nil, fmt.Errorf("target %s: %w", tf.Path, err)
	}
	return data, nil
}

func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return store.CheckDir(dir)
}

// storeMetadata writes the verified metadata, root first, each through an
// exclusive temp file with mode 0600.
func (c *Checker) storeMetadata(files map[string][]byte) error {
	if err := mkdirPrivate(filepath.Join(c.cfg.Dir, metaDir)); err != nil {
		return err
	}
	for _, name := range []string{"root.json", "timestamp.json", "snapshot.json", "targets.json"} {
		b, ok := files[name]
		if !ok {
			continue
		}
		if err := store.WriteFileAtomic(c.metaPath(name), b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
			return err
		}
	}
	return nil
}
