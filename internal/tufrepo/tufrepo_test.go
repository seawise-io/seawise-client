package tufrepo

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func TestInitTestRepoVerifies(t *testing.T) {
	dir := t.TempDir()
	keys, err := InitTest(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile(filepath.Join(dir, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsTestRoot(root) {
		t.Fatal("test root not marked")
	}
	rep, err := Verify(dir, root, t0.Add(time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.RootVersion != 1 || rep.TargetsVersion != 1 || rep.SnapshotVersion != 1 || rep.TimestampVersion != 1 {
		t.Fatalf("versions %+v", rep)
	}
	for _, f := range []string{"root-primary", "root-backup", "targets", "snapshot", "timestamp"} {
		fi, err := os.Stat(filepath.Join(dir, "keys", f+".pem"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode())
		}
	}
}

func TestInitRefusesSingleRootKeyAndExistingRepo(t *testing.T) {
	k := mustKey(t)
	opts := InitOptions{
		Root:          RoleKeys{Keys: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Threshold: 1},
		Targets:       RoleKeys{Keys: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Threshold: 1},
		Snapshot:      RoleKeys{Keys: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Threshold: 1},
		Timestamp:     RoleKeys{Keys: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Threshold: 1},
		RootSigners:   []ed25519.PrivateKey{k},
		TargetsSigner: k,
		Now:           t0,
	}
	if err := Init(t.TempDir(), opts); err == nil || !strings.Contains(err.Error(), "two root keys") {
		t.Fatalf("single root key: %v", err)
	}
	dir := t.TempDir()
	if _, err := InitTest(dir, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := InitTest(dir, t0); err == nil {
		t.Fatal("init over an existing repo")
	}
}

func TestSignTargetsAndRefresh(t *testing.T) {
	dir := t.TempDir()
	keys, err := InitTest(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	v, err := SignTargets(dir, keys.Targets, map[string][]byte{"keyset.json": []byte(`{"v":1}`), "release/stable.json": []byte(`{}`)}, nil, t0, DefaultTargetsExpiry)
	if err != nil || v != 2 {
		t.Fatalf("sign targets: v=%d %v", v, err)
	}
	res, err := Refresh(dir, keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NewSnapshot || res.SnapshotVersion != 1 || res.TimestampVersion != 1 {
		t.Fatalf("first refresh %+v", res)
	}
	// Nothing changed and the snapshot is new: only a timestamp.
	res, err = Refresh(dir, keys.Snapshot, keys.Timestamp, t0.Add(24*time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewSnapshot || res.TimestampVersion != 2 {
		t.Fatalf("second refresh %+v", res)
	}
	// Half way through the snapshot's life it is renewed.
	res, err = Refresh(dir, keys.Snapshot, keys.Timestamp, t0.Add(8*24*time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NewSnapshot || res.SnapshotVersion != 2 {
		t.Fatalf("weekly refresh %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "targets", "release")); err != nil {
		t.Fatal("nested target not written under its folder")
	}
	root, _ := os.ReadFile(filepath.Join(dir, "metadata", "1.root.json"))
	rep, err := Verify(dir, root, t0.Add(8*24*time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Targets) != 2 {
		t.Fatalf("targets %v", rep.Targets)
	}
	v, err = SignTargets(dir, keys.Targets, nil, []string{"keyset.json"}, t0, DefaultTargetsExpiry)
	if err != nil || v != 3 {
		t.Fatalf("remove: %d %v", v, err)
	}
}

func TestSignRefusesWrongKeys(t *testing.T) {
	dir := t.TempDir()
	keys, err := InitTest(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignTargets(dir, keys.Snapshot, map[string][]byte{"keyset.json": []byte("x")}, nil, t0, DefaultTargetsExpiry); err == nil {
		t.Fatal("targets signed with the snapshot key")
	}
	if _, err := Refresh(dir, keys.Timestamp, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err == nil {
		t.Fatal("snapshot signed with the timestamp key")
	}
	if _, err := SignTargets(dir, keys.Targets, map[string][]byte{"../x": []byte("x")}, nil, t0, DefaultTargetsExpiry); err == nil {
		t.Fatal("bad target name accepted")
	}
}

func TestRotateRoot(t *testing.T) {
	dir := t.TempDir()
	keys, err := InitTest(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	newTS := mustKey(t)
	// The backup root key alone may sign a rotation.
	v, err := RotateRoot(dir, RootChange{
		Roles:   map[string]RoleKeys{metadata.TIMESTAMP: {Keys: []ed25519.PublicKey{newTS.Public().(ed25519.PublicKey)}, Threshold: 1}},
		Signers: []ed25519.PrivateKey{keys.RootBackup},
		Now:     t0, Expires: DefaultRootExpiry,
	})
	if err != nil || v != 2 {
		t.Fatalf("rotate: %d %v", v, err)
	}
	// Replacing both root keys needs the old and the new keys.
	n1, n2 := mustKey(t), mustKey(t)
	newRoot := RoleKeys{Keys: []ed25519.PublicKey{n1.Public().(ed25519.PublicKey), n2.Public().(ed25519.PublicKey)}, Threshold: 1}
	if _, err := RotateRoot(dir, RootChange{Roles: map[string]RoleKeys{metadata.ROOT: newRoot}, Signers: []ed25519.PrivateKey{n1}, Now: t0, Expires: DefaultRootExpiry}); err == nil {
		t.Fatal("rotation signed only by new keys")
	}
	if _, err := RotateRoot(dir, RootChange{Roles: map[string]RoleKeys{metadata.ROOT: newRoot}, Signers: []ed25519.PrivateKey{keys.RootPrimary}, Now: t0, Expires: DefaultRootExpiry}); err == nil {
		t.Fatal("rotation not signed by the new keys")
	}
	if _, err := RotateRoot(dir, RootChange{Roles: map[string]RoleKeys{metadata.ROOT: newRoot}, Signers: []ed25519.PrivateKey{keys.RootPrimary, n1}, Now: t0, Expires: DefaultRootExpiry}); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, keys.Snapshot, newTS, t0, DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	root, _ := os.ReadFile(filepath.Join(dir, "metadata", "1.root.json"))
	rep, err := Verify(dir, root, t0.Add(time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.RootVersion != 3 {
		t.Fatalf("root version %d", rep.RootVersion)
	}
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.pem")
	id, err := Keygen(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(path); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite: %v", err)
	}
	k, err := LoadPrivateKey(path, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(k.Public()) {
		t.Fatal("public key mismatch")
	}
	if got, _ := KeyID(pub); got != id {
		t.Fatalf("key id %s != %s", got, id)
	}
	pem, _ := os.ReadFile(path)
	env := func(k string) string {
		if k == "TUF_KEY" {
			return string(pem)
		}
		return ""
	}
	k2, err := LoadPrivateKey("env:TUF_KEY", env)
	if err != nil || !k2.Equal(k) {
		t.Fatalf("env key: %v", err)
	}
	if _, err := LoadPrivateKey("env:MISSING", env); err == nil {
		t.Fatal("empty env key accepted")
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"14d": 14 * 24 * time.Hour, "36h": 36 * time.Hour, "365d": 365 * 24 * time.Hour} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0d", "-1d", "d", "1y"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPull(t *testing.T) {
	src := t.TempDir()
	keys, err := InitTest(src, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RotateRoot(src, RootChange{Signers: []ed25519.PrivateKey{keys.RootPrimary}, Now: t0, Expires: DefaultRootExpiry}); err != nil {
		t.Fatal(err)
	}
	if _, err := SignTargets(src, keys.Targets, map[string][]byte{"keyset.json": []byte("k")}, nil, t0, DefaultTargetsExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(src, keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.FileServer(http.Dir(src)))
	defer srv.Close()
	dst := t.TempDir()
	if err := Pull(context.Background(), srv.Client(), srv.URL, dst); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"1.root.json", "2.root.json", "timestamp.json", "1.snapshot.json", "2.targets.json"} {
		if _, err := os.Stat(filepath.Join(dst, "metadata", f)); err != nil {
			t.Fatal(err)
		}
	}
	root, _ := os.ReadFile(filepath.Join(src, "metadata", "1.root.json"))
	if _, err := Verify(dst, root, t0.Add(time.Hour), false); err != nil {
		t.Fatalf("metadata-only verify after pull: %v", err)
	}
	if _, err := Verify(dst, root, t0.Add(time.Hour), true); err == nil {
		t.Fatal("targets verified without target files")
	}
	if err := Pull(context.Background(), srv.Client(), "http://example.invalid", dst); err == nil {
		t.Fatal("http accepted")
	}
	// The pulled metadata is enough for the next online refresh.
	res, err := Refresh(dst, keys.Snapshot, keys.Timestamp, t0.Add(time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil || res.TimestampVersion != 2 {
		t.Fatalf("refresh after pull: %+v %v", res, err)
	}
}
