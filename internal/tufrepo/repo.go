// Package tufrepo builds and maintains a static TUF repository with
// consistent snapshots: every file except metadata/timestamp.json is
// immutable, so any static host can serve it with no server logic.
//
//	metadata/<n>.root.json      offline root keys
//	metadata/<n>.targets.json   offline targets key
//	metadata/<n>.snapshot.json  online snapshot key
//	metadata/timestamp.json     online timestamp key
//	targets/[dir/]<sha256>.<name>
//
// It is used by tools/tuf and by tests; the agent does not import it.
package tufrepo

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// TestOnlyField marks a root as test-only inside its signed part. The agent
// refuses such a root outside tests.
const TestOnlyField = "x-seawise-test-only"

const (
	DefaultRootExpiry    = 365 * 24 * time.Hour
	DefaultTargetsExpiry = 120 * 24 * time.Hour
	DefaultOnlineExpiry  = 14 * 24 * time.Hour
	DefaultMinRemaining  = 7 * 24 * time.Hour

	// MaxTargetSize caps a single target file.
	MaxTargetSize = 1 << 20
)

var targetName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)

// RoleKeys is the key list and threshold of one top-level role.
type RoleKeys struct {
	Keys      []ed25519.PublicKey
	Threshold int
}

// InitOptions describes a new repository. Snapshot and timestamp metadata
// are created later by the first Refresh, which needs the online keys.
type InitOptions struct {
	Root, Targets, Snapshot, Timestamp RoleKeys
	RootSigners                        []ed25519.PrivateKey
	TargetsSigner                      ed25519.PrivateKey
	Now                                time.Time
	RootExpires, TargetsExpires        time.Duration
	// TestOnly marks the root as a test root. Otherwise every key must be
	// listed in AllowedKeyIDs.
	TestOnly      bool
	AllowedKeyIDs []string
}

// MinRootThreshold is the smallest root threshold accepted; the root role
// must also hold at least one key more than its threshold, so losing one
// root key does not need a client release.
const MinRootThreshold = 2

func checkRootRole(rk RoleKeys) error {
	if rk.Threshold < MinRootThreshold || len(rk.Keys) < rk.Threshold+1 {
		return fmt.Errorf("the root role needs a threshold of at least %d and one key more than the threshold (default 2 of 3)", MinRootThreshold)
	}
	return nil
}

// Init writes 1.root.json and 1.targets.json into a new repository.
func Init(dir string, o InitOptions) error {
	if err := checkRootRole(o.Root); err != nil {
		return err
	}
	if !o.TestOnly {
		if len(o.AllowedKeyIDs) == 0 {
			return errors.New("a production repository needs a key allowlist")
		}
		for _, rk := range []RoleKeys{o.Root, o.Targets, o.Snapshot, o.Timestamp} {
			for _, k := range rk.Keys {
				id, err := KeyID(k)
				if err != nil {
					return err
				}
				if !slices.Contains(o.AllowedKeyIDs, id) {
					return fmt.Errorf("key %s is not in the allowlist", id)
				}
			}
		}
	}
	if entries, err := os.ReadDir(filepath.Join(dir, "metadata")); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s already holds a repository", dir)
	}
	if o.RootExpires == 0 {
		o.RootExpires = DefaultRootExpiry
	}
	if o.TargetsExpires == 0 {
		o.TargetsExpires = DefaultTargetsExpiry
	}
	root := metadata.Root(expiry(o.Now, o.RootExpires))
	if o.TestOnly {
		root.Signed.UnrecognizedFields = map[string]any{TestOnlyField: true}
	}
	for role, rk := range map[string]RoleKeys{metadata.ROOT: o.Root, metadata.TARGETS: o.Targets, metadata.SNAPSHOT: o.Snapshot, metadata.TIMESTAMP: o.Timestamp} {
		if err := setRole(&root.Signed, role, rk); err != nil {
			return err
		}
	}
	if err := sign(root, o.RootSigners...); err != nil {
		return err
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		return fmt.Errorf("root signatures: %w", err)
	}
	targets := metadata.Targets(expiry(o.Now, o.TargetsExpires))
	if err := sign(targets, o.TargetsSigner); err != nil {
		return err
	}
	if err := root.VerifyDelegate(metadata.TARGETS, targets); err != nil {
		return fmt.Errorf("targets signature: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "metadata"), 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "targets"), 0o750); err != nil {
		return err
	}
	if err := writeMeta(dir, "1.root.json", root); err != nil {
		return err
	}
	return writeMeta(dir, "1.targets.json", targets)
}

// TestKeys are the keys of a test repository.
type TestKeys struct {
	Root                         []ed25519.PrivateKey // three keys, threshold 2
	Targets, Snapshot, Timestamp ed25519.PrivateKey
}

// TestKeysMarker is created in every test key folder; production commands
// refuse keys from a folder that holds it.
const TestKeysMarker = "TEST-KEYS-DO-NOT-USE"

// IsTestKeyPath reports whether a key file lies in a test key folder.
func IsTestKeyPath(ref string) bool {
	if strings.HasPrefix(ref, "env:") {
		return false
	}
	_, err := os.Lstat(filepath.Join(filepath.Dir(ref), TestKeysMarker))
	return err == nil
}

// InitTest creates a repository with fresh keys under dir/keys and a root
// marked test-only. Never use it for a real repository.
func InitTest(dir string, now time.Time) (*TestKeys, error) {
	if entries, err := os.ReadDir(filepath.Join(dir, "metadata")); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s already holds a repository", dir)
	}
	keyDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(keyDir, TestKeysMarker), []byte("Keys in this folder are for tests only.\n"), 0o600); err != nil {
		return nil, err
	}
	tk := TestKeys{Root: make([]ed25519.PrivateKey, 3)}
	gen := func(name string, dst *ed25519.PrivateKey) error {
		key, err := GenerateKey()
		if err != nil {
			return err
		}
		if err := writeKey(filepath.Join(keyDir, name+".pem"), key); err != nil {
			return err
		}
		*dst = key
		return nil
	}
	for i := range tk.Root {
		if err := gen(fmt.Sprintf("root-%d", i+1), &tk.Root[i]); err != nil {
			return nil, err
		}
	}
	for name, dst := range map[string]*ed25519.PrivateKey{"targets": &tk.Targets, "snapshot": &tk.Snapshot, "timestamp": &tk.Timestamp} {
		if err := gen(name, dst); err != nil {
			return nil, err
		}
	}
	one := func(k ed25519.PrivateKey) RoleKeys {
		return RoleKeys{Keys: []ed25519.PublicKey{pub(k)}, Threshold: 1}
	}
	err := Init(dir, InitOptions{
		Root:          RoleKeys{Keys: []ed25519.PublicKey{pub(tk.Root[0]), pub(tk.Root[1]), pub(tk.Root[2])}, Threshold: 2},
		Targets:       one(tk.Targets),
		Snapshot:      one(tk.Snapshot),
		Timestamp:     one(tk.Timestamp),
		RootSigners:   tk.Root[:2],
		TargetsSigner: tk.Targets,
		Now:           now,
		TestOnly:      true,
	})
	if err != nil {
		return nil, err
	}
	return &tk, nil
}

// IsTestRoot reports whether root metadata carries the test-only marker.
func IsTestRoot(b []byte) bool {
	r, err := metadata.Root().FromBytes(b)
	if err != nil {
		return false
	}
	v, ok := r.Signed.UnrecognizedFields[TestOnlyField]
	return ok && v != false
}

// SignTargets writes the next targets version with files added and names
// removed. File contents are copied to targets/ under their hash.
func SignTargets(dir string, key ed25519.PrivateKey, add map[string][]byte, remove []string, now time.Time, expires time.Duration) (int64, error) {
	root, _, err := LatestRoot(dir)
	if err != nil {
		return 0, err
	}
	prev, _, err := latest[metadata.TargetsType](dir, metadata.TARGETS)
	if err != nil {
		return 0, err
	}
	next := metadata.Targets(expiry(now, expires))
	next.Signed.Version = prev.Signed.Version + 1
	next.Signed.Targets = prev.Signed.Targets
	if next.Signed.Targets == nil {
		next.Signed.Targets = map[string]*metadata.TargetFiles{}
	}
	for _, name := range remove {
		if _, ok := next.Signed.Targets[name]; !ok {
			return 0, fmt.Errorf("target %q not present", name)
		}
		delete(next.Signed.Targets, name)
	}
	names := make([]string, 0, len(add))
	for name := range add {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		data := add[name]
		if err := checkTargetName(name); err != nil {
			return 0, err
		}
		if len(data) > MaxTargetSize {
			return 0, fmt.Errorf("target %q is larger than %d bytes", name, MaxTargetSize)
		}
		tf, err := metadata.TargetFile().FromBytes(name, data, "sha256")
		if err != nil {
			return 0, err
		}
		tf.Path = name
		next.Signed.Targets[name] = tf
	}
	if err := sign(next, key); err != nil {
		return 0, err
	}
	if err := root.VerifyDelegate(metadata.TARGETS, next); err != nil {
		return 0, fmt.Errorf("key is not a targets key of the current root: %w", err)
	}
	for _, name := range names {
		if err := writeTarget(dir, name, add[name]); err != nil {
			return 0, err
		}
	}
	return next.Signed.Version, writeMeta(dir, fmt.Sprintf("%d.targets.json", next.Signed.Version), next)
}

func checkTargetName(name string) error {
	if len(name) > 128 || !targetName.MatchString(name) {
		return fmt.Errorf("invalid target name %q", name)
	}
	return nil
}

func writeTarget(dir, name string, data []byte) error {
	sum := sha256.Sum256(data)
	sub, base := path.Split(name)
	d := filepath.Join(dir, "targets", filepath.FromSlash(sub))
	if err := os.MkdirAll(d, 0o750); err != nil {
		return err
	}
	return writeFile(filepath.Join(d, hex.EncodeToString(sum[:])+"."+base), data)
}

// RefreshResult reports what Refresh wrote.
type RefreshResult struct {
	NewSnapshot      bool
	SnapshotVersion  int64
	TimestampVersion int64
}

// Refresh writes a new timestamp and, when targets changed or the current
// snapshot has less than minRemaining left, a new snapshot. It first
// verifies the repository from trustedRoot (the pinned root) and builds
// only on the verified root, snapshot and timestamp versions, so forged
// files on the host cannot steer what the online keys sign.
func Refresh(dir string, trustedRoot []byte, snapshotKey, timestampKey ed25519.PrivateKey, now time.Time, expires, minRemaining time.Duration) (RefreshResult, error) {
	var res RefreshResult
	v, err := verifyState(dir, trustedRoot, now)
	if err != nil {
		return res, err
	}
	targets, targetsRaw, err := v.nextTargets(dir, now)
	if err != nil {
		return res, err
	}
	snap, snapRaw := v.snap, v.snapRaw
	if snap == nil || snap.Signed.Meta["targets.json"] == nil ||
		snap.Signed.Meta["targets.json"].Version != targets.Signed.Version ||
		snap.Signed.Expires.Sub(now) < minRemaining {
		next := metadata.Snapshot(expiry(now, expires))
		if snap != nil {
			next.Signed.Version = snap.Signed.Version + 1
		}
		next.Signed.Meta["targets.json"] = metaFile(targets.Signed.Version, targetsRaw)
		if err := sign(next, snapshotKey); err != nil {
			return res, err
		}
		if err := v.root.VerifyDelegate(metadata.SNAPSHOT, next); err != nil {
			return res, fmt.Errorf("key is not a snapshot key of the current root: %w", err)
		}
		raw, err := encode(next)
		if err != nil {
			return res, err
		}
		if err := writeFile(filepath.Join(dir, "metadata", fmt.Sprintf("%d.snapshot.json", next.Signed.Version)), raw); err != nil {
			return res, err
		}
		snap, snapRaw, res.NewSnapshot = next, raw, true
	}
	res.SnapshotVersion = snap.Signed.Version

	ts := metadata.Timestamp(expiry(now, expires))
	if v.ts != nil {
		ts.Signed.Version = v.ts.Signed.Version + 1
	}
	ts.Signed.Meta["snapshot.json"] = metaFile(snap.Signed.Version, snapRaw)
	if err := sign(ts, timestampKey); err != nil {
		return res, err
	}
	if err := v.root.VerifyDelegate(metadata.TIMESTAMP, ts); err != nil {
		return res, fmt.Errorf("key is not a timestamp key of the current root: %w", err)
	}
	res.TimestampVersion = ts.Signed.Version
	return res, writeMeta(dir, "timestamp.json", ts)
}

func metaFile(version int64, raw []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(raw)
	m := metadata.MetaFile(version)
	m.Length = int64(len(raw))
	m.Hashes = metadata.Hashes{"sha256": sum[:]}
	return m
}

// RootChange describes the next root version.
type RootChange struct {
	// Roles replaces the keys and threshold of each named role.
	Roles   map[string]RoleKeys
	Signers []ed25519.PrivateKey
	Now     time.Time
	Expires time.Duration
}

// RotateRoot writes the next root version. It must be signed by a
// threshold of the current root keys and of its own root keys.
func RotateRoot(dir string, ch RootChange) (int64, error) {
	cur, raw, err := LatestRoot(dir)
	if err != nil {
		return 0, err
	}
	next, err := metadata.Root().FromBytes(raw)
	if err != nil {
		return 0, err
	}
	next.ClearSignatures()
	next.Signed.Version = cur.Signed.Version + 1
	next.Signed.Expires = expiry(ch.Now, ch.Expires)
	for role, rk := range ch.Roles {
		if err := setRole(&next.Signed, role, rk); err != nil {
			return 0, err
		}
	}
	if r := next.Signed.Roles[metadata.ROOT]; r.Threshold < MinRootThreshold || len(r.KeyIDs) < r.Threshold+1 {
		return 0, checkRootRole(RoleKeys{Threshold: r.Threshold})
	}
	if err := sign(next, ch.Signers...); err != nil {
		return 0, err
	}
	if err := cur.VerifyDelegate(metadata.ROOT, next); err != nil {
		return 0, fmt.Errorf("not signed by the current root threshold: %w", err)
	}
	if err := next.VerifyDelegate(metadata.ROOT, next); err != nil {
		return 0, fmt.Errorf("not signed by the new root threshold: %w", err)
	}
	return next.Signed.Version, writeMeta(dir, fmt.Sprintf("%d.root.json", next.Signed.Version), next)
}

func setRole(r *metadata.RootType, role string, rk RoleKeys) error {
	if len(rk.Keys) == 0 || rk.Threshold < 1 || rk.Threshold > len(rk.Keys) {
		return fmt.Errorf("role %s: need 1 <= threshold <= keys", role)
	}
	if _, ok := r.Roles[role]; !ok {
		return fmt.Errorf("unknown role %q", role)
	}
	ids := make([]string, 0, len(rk.Keys))
	for _, k := range rk.Keys {
		tk, err := metadata.KeyFromPublicKey(k)
		if err != nil {
			return err
		}
		id, err := tk.ID()
		if err != nil {
			return err
		}
		if slices.Contains(ids, id) {
			return fmt.Errorf("role %s: duplicate key", role)
		}
		ids = append(ids, id)
		r.Keys[id] = tk
	}
	r.Roles[role] = &metadata.Role{KeyIDs: ids, Threshold: rk.Threshold}
	for id := range r.Keys {
		used := false
		for _, ro := range r.Roles {
			used = used || slices.Contains(ro.KeyIDs, id)
		}
		if !used {
			delete(r.Keys, id)
		}
	}
	return nil
}

func sign[T metadata.Roles](m *metadata.Metadata[T], keys ...ed25519.PrivateKey) error {
	var seen []string
	for _, k := range keys {
		if k == nil {
			return errors.New("missing signing key")
		}
		id, err := KeyID(pub(k))
		if err != nil {
			return err
		}
		if slices.Contains(seen, id) {
			continue
		}
		seen = append(seen, id)
		s, err := signature.LoadED25519Signer(k)
		if err != nil {
			return err
		}
		if _, err := m.Sign(s); err != nil {
			return err
		}
	}
	return nil
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func expiry(now time.Time, d time.Duration) time.Time {
	return now.Add(d).UTC().Truncate(time.Second)
}

func encode[T metadata.Roles](m *metadata.Metadata[T]) ([]byte, error) {
	return m.ToBytes(true)
}

func writeMeta[T metadata.Roles](dir, name string, m *metadata.Metadata[T]) error {
	raw, err := encode(m)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "metadata", name), raw)
}

// writeFile replaces path atomically so a host never serves a partial file.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func readMeta[T metadata.Roles](path string) (*metadata.Metadata[T], error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed metadata name under the operator's repository folder
	if err != nil {
		return nil, err
	}
	var m metadata.Metadata[T]
	return m.FromBytes(raw)
}

// LatestRoot returns the highest root version in the repository.
func LatestRoot(dir string) (*metadata.Metadata[metadata.RootType], []byte, error) {
	return latest[metadata.RootType](dir, metadata.ROOT)
}

func latest[T metadata.Roles](dir, role string) (*metadata.Metadata[T], []byte, error) {
	v, err := latestVersion(filepath.Join(dir, "metadata"), role)
	if err != nil {
		return nil, nil, err
	}
	// #nosec G304 -- versioned metadata name under the operator's repository folder
	raw, err := os.ReadFile(filepath.Join(dir, "metadata", fmt.Sprintf("%d.%s.json", v, role)))
	if err != nil {
		return nil, nil, err
	}
	var m metadata.Metadata[T]
	if _, err := m.FromBytes(raw); err != nil {
		return nil, nil, fmt.Errorf("%d.%s.json: %w", v, role, err)
	}
	return &m, raw, nil
}

func latestVersion(metaDir, role string) (int64, error) {
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		return 0, err
	}
	var best int64
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), "."+role+".json")
		if !ok {
			continue
		}
		v, err := strconv.ParseInt(n, 10, 64)
		if err == nil && v > best {
			best = v
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("no %s metadata: %w", role, os.ErrNotExist)
	}
	return best, nil
}
