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

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func rootBytes(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func initRefreshed(t *testing.T) (string, *TestKeys) {
	t.Helper()
	dir := t.TempDir()
	keys, err := InitTest(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, rootBytes(t, dir), keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	return dir, keys
}

func TestInitTestRepoVerifies(t *testing.T) {
	dir, _ := initRefreshed(t)
	root := rootBytes(t, dir)
	if !IsTestRoot(root) {
		t.Fatal("test root not marked")
	}
	r, _ := metadata.Root().FromBytes(root)
	if role := r.Signed.Roles[metadata.ROOT]; role.Threshold != 2 || len(role.KeyIDs) != 3 {
		t.Fatalf("root role %+v, want 2 of 3", role)
	}
	rep, err := Verify(dir, root, t0.Add(time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.RootVersion != 1 || rep.TargetsVersion != 1 || rep.SnapshotVersion != 1 || rep.TimestampVersion != 1 {
		t.Fatalf("versions %+v", rep)
	}
	for _, f := range []string{"root-1", "root-2", "root-3", "targets", "snapshot", "timestamp"} {
		fi, err := os.Stat(filepath.Join(dir, "keys", f+".pem"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, fi.Mode())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "keys", TestKeysMarker)); err != nil {
		t.Fatal("test key folder not marked")
	}
}

func prodKeys(t *testing.T, n int) ([]ed25519.PrivateKey, []ed25519.PublicKey, []string) {
	t.Helper()
	var privs []ed25519.PrivateKey
	var pubs []ed25519.PublicKey
	var ids []string
	for i := 0; i < n; i++ {
		k := mustKey(t)
		privs = append(privs, k)
		pubs = append(pubs, pub(k))
		id, _ := KeyID(pub(k))
		ids = append(ids, id)
	}
	return privs, pubs, ids
}

func prodOptions(t *testing.T) InitOptions {
	privs, pubs, ids := prodKeys(t, 6)
	one := func(i int) RoleKeys { return RoleKeys{Keys: []ed25519.PublicKey{pubs[i]}, Threshold: 1} }
	return InitOptions{
		Root:          RoleKeys{Keys: pubs[:3], Threshold: 2},
		Targets:       one(3),
		Snapshot:      one(4),
		Timestamp:     one(5),
		RootSigners:   privs[:2],
		TargetsSigner: privs[3],
		Now:           t0,
		AllowedKeyIDs: ids,
	}
}

func TestInitRootThresholdAndAllowlist(t *testing.T) {
	if err := Init(t.TempDir(), prodOptions(t)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*InitOptions){
		"threshold 1":          func(o *InitOptions) { o.Root.Threshold = 1 },
		"two of two":           func(o *InitOptions) { o.Root.Keys = o.Root.Keys[:2] },
		"one signature":        func(o *InitOptions) { o.RootSigners = o.RootSigners[:1] },
		"no allowlist":         func(o *InitOptions) { o.AllowedKeyIDs = nil },
		"key not in allowlist": func(o *InitOptions) { o.AllowedKeyIDs = o.AllowedKeyIDs[1:] },
	}
	for name, mod := range cases {
		o := prodOptions(t)
		mod(&o)
		if err := Init(t.TempDir(), o); err == nil {
			t.Errorf("%s accepted", name)
		}
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
	dir, keys := initRefreshed(t)
	root := rootBytes(t, dir)
	v, err := SignTargets(dir, keys.Targets, map[string][]byte{"keyset.json": []byte(`{"v":1}`), "release/stable.json": []byte(`{}`)}, nil, t0, DefaultTargetsExpiry)
	if err != nil || v != 2 {
		t.Fatalf("sign targets: v=%d %v", v, err)
	}
	res, err := Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NewSnapshot || res.SnapshotVersion != 2 || res.TimestampVersion != 2 {
		t.Fatalf("refresh after new targets %+v", res)
	}
	res, err = Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0.Add(24*time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewSnapshot || res.TimestampVersion != 3 {
		t.Fatalf("unchanged refresh %+v", res)
	}
	res, err = Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0.Add(8*24*time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NewSnapshot || res.SnapshotVersion != 3 {
		t.Fatalf("weekly refresh %+v", res)
	}
	// After the online roles expired (a missed week), refresh still works.
	res, err = Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0.Add(30*24*time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil || !res.NewSnapshot {
		t.Fatalf("refresh after expiry %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "targets", "release")); err != nil {
		t.Fatal("nested target not written under its folder")
	}
	rep, err := Verify(dir, root, t0.Add(30*24*time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Targets) != 2 {
		t.Fatalf("targets %v", rep.Targets)
	}
	if v, err = SignTargets(dir, keys.Targets, nil, []string{"keyset.json"}, t0, DefaultTargetsExpiry); err != nil || v != 3 {
		t.Fatalf("remove: %d %v", v, err)
	}
}

func TestRefreshRefusesForgedState(t *testing.T) {
	dir, keys := initRefreshed(t)
	root := rootBytes(t, dir)
	// A timestamp on the host signed by a key the root does not trust.
	evil := mustKey(t)
	ts, _ := metadata.Timestamp().FromBytes(mustRead(t, dir, "timestamp.json"))
	ts.Signed.Version = 50
	resign(t, dir, ts, evil)
	if _, err := Refresh(dir, root, keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err == nil {
		t.Fatal("refresh built on a forged timestamp")
	}
	// Targets on the host not signed by the targets key.
	dir, keys = initRefreshed(t)
	tg := metadata.Targets(t0.Add(time.Hour))
	tg.Signed.Version = 2
	s, _ := signature.LoadED25519Signer(evil)
	_, _ = tg.Sign(s)
	if err := writeMeta(dir, "2.targets.json", tg); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, rootBytes(t, dir), keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err == nil {
		t.Fatal("refresh referenced unsigned targets")
	}
	// Starting from a root that is not this repository's.
	other := t.TempDir()
	if _, err := InitTest(other, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, rootBytes(t, other), keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err == nil {
		t.Fatal("refresh with a foreign root")
	}
}

func mustRead(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "metadata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// resign replaces dir's timestamp.json with ts signed by k.
func resign(t *testing.T, dir string, ts *metadata.Metadata[metadata.TimestampType], k ed25519.PrivateKey) {
	t.Helper()
	ts.ClearSignatures()
	s, _ := signature.LoadED25519Signer(k)
	if _, err := ts.Sign(s); err != nil {
		t.Fatal(err)
	}
	if err := writeMeta(dir, "timestamp.json", ts); err != nil {
		t.Fatal(err)
	}
}

func TestSignRefusesWrongKeys(t *testing.T) {
	dir, keys := initRefreshed(t)
	if _, err := SignTargets(dir, keys.Snapshot, map[string][]byte{"keyset.json": []byte("x")}, nil, t0, DefaultTargetsExpiry); err == nil {
		t.Fatal("targets signed with the snapshot key")
	}
	if _, err := SignTargets(dir, keys.Targets, map[string][]byte{"keyset.json": []byte("x")}, nil, t0, DefaultTargetsExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, rootBytes(t, dir), keys.Timestamp, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err == nil {
		t.Fatal("snapshot signed with the timestamp key")
	}
	if _, err := SignTargets(dir, keys.Targets, map[string][]byte{"../x": []byte("x")}, nil, t0, DefaultTargetsExpiry); err == nil {
		t.Fatal("bad target name accepted")
	}
}

func TestRotateRoot(t *testing.T) {
	dir, keys := initRefreshed(t)
	root := rootBytes(t, dir)
	newTS := mustKey(t)
	// Root key 1 is lost: keys 2 and 3 sign a rotation of the timestamp key.
	v, err := RotateRoot(dir, RootChange{
		Roles:   map[string]RoleKeys{metadata.TIMESTAMP: {Keys: []ed25519.PublicKey{pub(newTS)}, Threshold: 1}},
		Signers: keys.Root[1:],
		Now:     t0, Expires: DefaultRootExpiry,
	})
	if err != nil || v != 2 {
		t.Fatalf("rotate: %d %v", v, err)
	}
	if _, err := RotateRoot(dir, RootChange{Signers: keys.Root[:1], Now: t0, Expires: DefaultRootExpiry}); err == nil {
		t.Fatal("rotation with one of three root signatures")
	}
	// Replacing the root keys needs a threshold of the old and of the new keys.
	n, nPub, _ := prodKeys(t, 3)
	newRoot := RoleKeys{Keys: nPub, Threshold: 2}
	for name, signers := range map[string][]ed25519.PrivateKey{
		"only new": n[:2],
		"only old": keys.Root[:2],
		"one new":  {keys.Root[0], keys.Root[1], n[0]},
	} {
		if _, err := RotateRoot(dir, RootChange{Roles: map[string]RoleKeys{metadata.ROOT: newRoot}, Signers: signers, Now: t0, Expires: DefaultRootExpiry}); err == nil {
			t.Errorf("rotation signed %s accepted", name)
		}
	}
	for name, rk := range map[string]RoleKeys{"threshold 1": {Keys: nPub, Threshold: 1}, "two of two": {Keys: nPub[:2], Threshold: 2}} {
		if _, err := RotateRoot(dir, RootChange{Roles: map[string]RoleKeys{metadata.ROOT: rk}, Signers: append(keys.Root[:2:2], n...), Now: t0, Expires: DefaultRootExpiry}); err == nil {
			t.Errorf("root %s accepted", name)
		}
	}
	if _, err := RotateRoot(dir, RootChange{Roles: map[string]RoleKeys{metadata.ROOT: newRoot}, Signers: append(keys.Root[1:3:3], n[0], n[2]), Now: t0, Expires: DefaultRootExpiry}); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(dir, root, keys.Snapshot, newTS, t0, DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
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
	// An existing public key file is never replaced either.
	other := filepath.Join(dir, "o.pem")
	if err := os.WriteFile(other+".pub", []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(other); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrote a .pub: %v", err)
	}
	if b, _ := os.ReadFile(other + ".pub"); string(b) != "keep" {
		t.Fatal(".pub replaced")
	}
	if _, err := os.Stat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private key left behind without its public key")
	}
	k, err := LoadPrivateKey(path, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := LoadPublicKey(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(k.Public()) {
		t.Fatal("public key mismatch")
	}
	if got, _ := KeyID(pk); got != id {
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

func TestIsTestKeyPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := InitTest(dir, t0); err != nil {
		t.Fatal(err)
	}
	if !IsTestKeyPath(filepath.Join(dir, "keys", "root-1.pem")) || !IsTestKeyPath(filepath.Join(dir, "keys", "root-1.pem.pub")) {
		t.Fatal("test key not recognised")
	}
	if IsTestKeyPath(filepath.Join(t.TempDir(), "root.pem")) || IsTestKeyPath("env:KEY") {
		t.Fatal("non-test key flagged")
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

func TestPull(t *testing.T) {
	src, keys := initRefreshed(t)
	root := rootBytes(t, src)
	if _, err := RotateRoot(src, RootChange{Signers: keys.Root[:2], Now: t0, Expires: DefaultRootExpiry}); err != nil {
		t.Fatal(err)
	}
	if _, err := SignTargets(src, keys.Targets, map[string][]byte{"keyset.json": []byte("k")}, nil, t0, DefaultTargetsExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(src, root, keys.Snapshot, keys.Timestamp, t0, DefaultOnlineExpiry, DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	override := map[string][]byte{}
	files := http.FileServer(http.Dir(src))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-mu
		b, ok := override[r.URL.Path]
		mu <- struct{}{}
		if ok {
			_, _ = w.Write(b)
			return
		}
		files.ServeHTTP(w, r)
	}))
	defer srv.Close()
	dst := t.TempDir()
	if err := Pull(context.Background(), srv.Client(), srv.URL, dst, root, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"2.root.json", "timestamp.json", "2.snapshot.json", "2.targets.json"} {
		if _, err := os.Stat(filepath.Join(dst, "metadata", f)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Verify(dst, root, t0.Add(time.Hour), false); err != nil {
		t.Fatalf("metadata-only verify after pull: %v", err)
	}
	if err := Pull(context.Background(), srv.Client(), "http://example.invalid", t.TempDir(), root, t0); err == nil {
		t.Fatal("http accepted")
	}
	// The pulled metadata is enough for the next online refresh.
	res, err := Refresh(dst, root, keys.Snapshot, keys.Timestamp, t0.Add(time.Hour), DefaultOnlineExpiry, DefaultMinRemaining)
	if err != nil || res.TimestampVersion != 3 {
		t.Fatalf("refresh after pull: %+v %v", res, err)
	}

	// A host serving forged metadata: nothing is written.
	evil := mustKey(t)
	ts, _ := metadata.Timestamp().FromBytes(mustRead(t, src, "timestamp.json"))
	ts.Signed.Version = 99
	ts.ClearSignatures()
	s, _ := signature.LoadED25519Signer(evil)
	_, _ = ts.Sign(s)
	forged, _ := ts.ToBytes(true)
	<-mu
	override["/metadata/timestamp.json"] = forged
	mu <- struct{}{}
	clean := t.TempDir()
	if err := Pull(context.Background(), srv.Client(), srv.URL, clean, root, t0.Add(time.Hour)); err == nil {
		t.Fatal("forged timestamp pulled")
	}
	if entries, _ := os.ReadDir(filepath.Join(clean, "metadata")); len(entries) != 0 {
		t.Fatalf("unverified files written: %v", entries)
	}
	// Pulling with a root that is not the repository's fails too.
	other := t.TempDir()
	if _, err := InitTest(other, t0); err != nil {
		t.Fatal(err)
	}
	<-mu
	delete(override, "/metadata/timestamp.json")
	mu <- struct{}{}
	if err := Pull(context.Background(), srv.Client(), srv.URL, t.TempDir(), rootBytes(t, other), t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("foreign root: %v", err)
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
