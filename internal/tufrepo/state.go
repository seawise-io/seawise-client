package tufrepo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

// verified is the repository state reached from a trusted root by the TUF
// checks: the root chain, then timestamp, snapshot and targets. Before the
// first refresh there is no timestamp, snapshot or targets in it.
type verified struct {
	root    *metadata.Metadata[metadata.RootType]
	rootRaw []byte
	ts      *metadata.Metadata[metadata.TimestampType]
	tsRaw   []byte
	snap    *metadata.Metadata[metadata.SnapshotType]
	snapRaw []byte
	targets *metadata.Metadata[metadata.TargetsType]
	tgRaw   []byte
	files   map[string][]byte // verified metadata files by name
}

// verifyState checks the metadata in dir starting from trustedRoot.
// Signatures, thresholds, versions, lengths and hashes are always checked.
// The online roles may have expired (that is what a refresh repairs), so
// they are checked at a reference time just before their expiry; the root
// must be unexpired at now.
func verifyState(dir string, trustedRoot []byte, now time.Time) (*verified, error) {
	tm, err := trustedmetadata.New(trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("trusted root: %w", err)
	}
	v := &verified{files: map[string][]byte{}}
	roots := [][]byte{trustedRoot}
	if raw, err := readRepo(dir, fmt.Sprintf("%d.root.json", tm.Root.Signed.Version)); err == nil {
		if string(raw) != string(trustedRoot) {
			return nil, errors.New("root metadata in the repository differs from the trusted root")
		}
		v.files[fmt.Sprintf("%d.root.json", tm.Root.Signed.Version)] = raw
	}
	for n := tm.Root.Signed.Version + 1; ; n++ {
		name := fmt.Sprintf("%d.root.json", n)
		raw, err := readRepo(dir, name)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, err
		}
		if _, err := tm.UpdateRoot(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		v.files[name] = raw
		roots = append(roots, raw)
	}
	v.root, v.rootRaw = tm.Root, roots[len(roots)-1]
	if v.root.Signed.IsExpired(now) {
		return nil, errors.New("root metadata has expired; sign a new root offline")
	}

	tsRaw, err := readRepo(dir, "timestamp.json")
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, err
	}
	// Unverified peek, used only to choose the reference time and names.
	ref := now
	peekTS, err := metadata.Timestamp().FromBytes(tsRaw)
	if err != nil {
		return nil, fmt.Errorf("timestamp.json: %w", err)
	}
	ref = before(ref, peekTS.Signed.Expires)
	sm := peekTS.Signed.Meta["snapshot.json"]
	if sm == nil {
		return nil, errors.New("timestamp has no snapshot entry")
	}
	snapName := fmt.Sprintf("%d.snapshot.json", sm.Version)
	snapRaw, err := readRepo(dir, snapName)
	if err != nil {
		return nil, err
	}
	if peek, err := metadata.Snapshot().FromBytes(snapRaw); err == nil {
		ref = before(ref, peek.Signed.Expires)
	}

	// The published online metadata was signed under the root in force at
	// the time; after a key rotation that is an earlier root of the
	// verified chain. Try the newest root first.
	var lastErr error
	for i := len(roots) - 1; i >= 0; i-- {
		on, err := verifyOnline(dir, roots[i], ref, tsRaw, snapName, snapRaw)
		if err != nil {
			lastErr = err
			continue
		}
		v.ts, v.snap, v.targets = on.ts, on.snap, on.targets
		v.tsRaw, v.snapRaw, v.tgRaw = tsRaw, snapRaw, on.tgRaw
		v.files["timestamp.json"], v.files[snapName], v.files[on.tgName] = tsRaw, snapRaw, on.tgRaw
		return v, nil
	}
	return nil, lastErr
}

type online struct {
	ts      *metadata.Metadata[metadata.TimestampType]
	snap    *metadata.Metadata[metadata.SnapshotType]
	targets *metadata.Metadata[metadata.TargetsType]
	tgName  string
	tgRaw   []byte
}

func verifyOnline(dir string, rootRaw []byte, ref time.Time, tsRaw []byte, snapName string, snapRaw []byte) (*online, error) {
	tm, err := trustedmetadata.New(rootRaw)
	if err != nil {
		return nil, err
	}
	tm.RefTime = ref
	var o online
	if o.ts, err = tm.UpdateTimestamp(tsRaw); err != nil {
		return nil, fmt.Errorf("timestamp.json: %w", err)
	}
	if o.snap, err = tm.UpdateSnapshot(snapRaw, false); err != nil {
		return nil, fmt.Errorf("%s: %w", snapName, err)
	}
	tmeta := o.snap.Signed.Meta["targets.json"]
	if tmeta == nil {
		return nil, errors.New("snapshot has no targets entry")
	}
	o.tgName = fmt.Sprintf("%d.targets.json", tmeta.Version)
	if o.tgRaw, err = readRepo(dir, o.tgName); err != nil {
		return nil, err
	}
	// Targets expiry is checked at now where it matters (nextTargets);
	// expiry is the last check go-tuf makes, after hashes and signatures.
	if o.targets, err = tm.UpdateTargets(o.tgRaw); err != nil {
		var exp *metadata.ErrExpiredMetadata
		if !errors.As(err, &exp) {
			return nil, fmt.Errorf("%s: %w", o.tgName, err)
		}
		if o.targets, err = metadata.Targets().FromBytes(o.tgRaw); err != nil {
			return nil, err
		}
	}
	return &o, nil
}

// before returns the earlier of t and one second before limit; a zero
// limit leaves t unchanged.
func before(t, limit time.Time) time.Time {
	if limit.IsZero() {
		return t
	}
	if l := limit.Add(-time.Second); l.Before(t) {
		return l
	}
	return t
}

// nextTargets returns the targets metadata the next snapshot should name:
// the newest N.targets.json signed by the verified root's targets role,
// not older than the verified one and unexpired at now.
func (v *verified) nextTargets(dir string, now time.Time) (*metadata.Metadata[metadata.TargetsType], []byte, error) {
	cand, raw, err := latest[metadata.TargetsType](dir, metadata.TARGETS)
	if err != nil {
		return nil, nil, err
	}
	if cand.Signed.Type != metadata.TARGETS {
		return nil, nil, errors.New("targets metadata has the wrong type")
	}
	if err := v.root.VerifyDelegate(metadata.TARGETS, cand); err != nil {
		return nil, nil, fmt.Errorf("%d.targets.json is not signed by the targets key: %w", cand.Signed.Version, err)
	}
	if v.targets != nil && cand.Signed.Version < v.targets.Signed.Version {
		return nil, nil, errors.New("newest targets metadata is older than the published one")
	}
	if cand.Signed.IsExpired(now) {
		return nil, nil, errors.New("targets metadata has expired; sign new targets offline")
	}
	return cand, raw, nil
}

func readRepo(dir, name string) ([]byte, error) {
	// #nosec G304 -- fixed or versioned metadata name under the operator's repository folder
	return os.ReadFile(filepath.Join(dir, "metadata", name))
}
