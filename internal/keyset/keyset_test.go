package keyset

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/protocol"
)

var t0 = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)

type vecKey struct {
	Name string `json:"name"`
	Seed string `json:"seed"`
	X    string `json:"x"`
}

func vectorKeys(t *testing.T) map[string]vecKey {
	t.Helper()
	b, err := os.ReadFile("../../testdata/vectors/keyset.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys []vecKey `json:"keys"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]vecKey{}
	for _, k := range f.Keys {
		out[k.Name] = k
	}
	return out
}

func priv(t *testing.T, k vecKey) ed25519.PrivateKey {
	t.Helper()
	s, err := hex.DecodeString(k.Seed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(s)
}

func pub(t *testing.T, k vecKey) ed25519.PublicKey {
	return priv(t, k).Public().(ed25519.PublicKey)
}

func roots(t *testing.T) []ed25519.PublicKey {
	v := vectorKeys(t)
	return []ed25519.PublicKey{pub(t, v["root-primary"]), pub(t, v["root-backup"])}
}

func entry(t *testing.T, k vecKey, role, status, name string) protocol.KeySetEntry {
	p := pub(t, k)
	return protocol.KeySetEntry{KID: protocol.KeyID(p), Role: role, X: k.X, Status: status, Name: name}
}

// signSet signs a set with the vector primary root holding control-1 and
// one edge key.
func signSet(t *testing.T, version int64, signer string) []byte {
	t.Helper()
	v := vectorKeys(t)
	tok, err := protocol.NewKeySet(priv(t, v[signer]), version, t0.Unix(), []protocol.KeySetEntry{
		entry(t, v["control-1"], protocol.RoleControl, protocol.StatusActive, ""),
		entry(t, v["edge-1"], protocol.RoleEdge, protocol.StatusActive, "edge-us-east-1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

func newManager(t *testing.T, dir string, now *time.Time) *Manager {
	t.Helper()
	m, err := New(Config{Dir: dir, Roots: roots(t), AllowTestRoots: true, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPlatformKeySetAccepted(t *testing.T) {
	tok, err := os.ReadFile("../../testdata/tuf-repo/keyset-v6.jws")
	if err != nil {
		t.Fatal(err)
	}
	now := t0
	m := newManager(t, stateDir(t), &now)
	if m.Current() != nil || m.Hold() != HoldMissing {
		t.Fatalf("fresh manager: %v %q", m.Current(), m.Hold())
	}
	if err := m.Offer(tok); err != nil {
		t.Fatal(err)
	}
	if ks := m.Current(); ks == nil || ks.Version != 6 {
		t.Fatalf("current %+v", ks)
	}
	if h := m.Hold(); h != "" {
		t.Fatalf("hold %q", h)
	}
}

func TestOfferPersistsAndReloads(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if err := m.Offer(signSet(t, 3, "root-primary")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dir, StateFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file %v %v", info, err)
	}
	m2 := newManager(t, dir, &now)
	if ks := m2.Current(); ks == nil || ks.Version != 3 {
		t.Fatalf("reloaded %+v", ks)
	}
	// The backup root is pinned too.
	if err := m2.Offer(signSet(t, 4, "root-backup")); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackRefusedAndFloorKept(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if err := m.Offer(signSet(t, 5, "root-primary")); err != nil {
		t.Fatal(err)
	}
	err := m.Offer(signSet(t, 4, "root-primary"))
	if protocol.CodeOf(err) != protocol.CodeRollback {
		t.Fatalf("older version: %v", err)
	}
	// Same version, another payload.
	v := vectorKeys(t)
	other, _ := protocol.NewKeySet(priv(t, v["root-primary"]), 5, t0.Unix()+1, []protocol.KeySetEntry{
		entry(t, v["control-2"], protocol.RoleControl, protocol.StatusActive, ""),
	})
	if err := m.Offer([]byte(other)); protocol.CodeOf(err) != protocol.CodeRollback {
		t.Fatalf("same version other payload: %v", err)
	}
	if ks := m.Current(); ks.Version != 5 {
		t.Fatalf("current %d", ks.Version)
	}
	// After a restart too.
	if err := newManager(t, dir, &now).Offer(signSet(t, 4, "root-primary")); protocol.CodeOf(err) != protocol.CodeRollback {
		t.Fatalf("after restart: %v", err)
	}
	// The same set again extends its freshness.
	if err := m.Offer(signSet(t, 5, "root-primary")); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(2 * time.Hour)
	if h := m.Hold(); h != "" {
		t.Fatalf("hold %q after the same set was vouched for again", h)
	}
}

func TestRefusedOfferKeepsStoredSet(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if err := m.Offer(signSet(t, 2, "root-primary")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, StateFile))
	for name, tok := range map[string][]byte{
		"rogue root": signSet(t, 9, "root-rogue"),
		"garbage":    []byte("not a token"),
		"empty":      nil,
	} {
		if err := m.Offer(tok); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, StateFile))
	if string(before) != string(after) || m.Current().Version != 2 {
		t.Fatal("refused offer changed the stored set")
	}
}

// The key set never expires: an outage of any length keeps it usable for
// dialling, and nothing is ever deleted.
func TestKeySetNeverExpires(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if m.Hold() != HoldMissing {
		t.Fatal("no hold without a key set")
	}
	if err := m.Offer(signSet(t, 2, "root-primary")); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(10 * 365 * 24 * time.Hour)
	if h := m.Hold(); h != "" {
		t.Fatalf("hold %q years later", h)
	}
	if h := newManager(t, dir, &now).Hold(); h != "" {
		t.Fatalf("hold %q after a restart", h)
	}
	if st := m.Status(); st.Version != 2 || st.Hold != "" || st.VerifiedAt.IsZero() {
		t.Fatalf("status %+v", st)
	}
}

func TestVerifiedAtNeverMovesBack(t *testing.T) {
	now := t0
	m := newManager(t, stateDir(t), &now)
	if err := m.Offer(signSet(t, 2, "root-primary")); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(-1000 * time.Hour)
	if err := m.Offer(signSet(t, 2, "root-primary")); err != nil {
		t.Fatal(err)
	}
	if got := m.Status().VerifiedAt; !got.Equal(t0) {
		t.Fatalf("verified at %v", got)
	}
}

func TestStoredStateChecks(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if err := m.Offer(signSet(t, 2, "root-primary")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, StateFile)
	orig, _ := os.ReadFile(path)
	restore := func() {
		_ = os.Remove(path)
		if err := os.WriteFile(path, orig, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if newManager(t, dir, &now).Current() != nil {
		t.Fatal("group-readable state used")
	}

	restore()
	elsewhere := filepath.Join(t.TempDir(), "s.json")
	_ = os.WriteFile(elsewhere, orig, 0o600)
	_ = os.Remove(path)
	_ = os.Symlink(elsewhere, path)
	if newManager(t, dir, &now).Current() != nil {
		t.Fatal("symlinked state used")
	}

	// A token that does not match the recorded digest.
	restore()
	var s stored
	_ = json.Unmarshal(orig, &s)
	s.Token = string(signSet(t, 7, "root-primary"))
	b, _ := json.Marshal(s)
	_ = os.Remove(path)
	_ = os.WriteFile(path, b, 0o600)
	if newManager(t, dir, &now).Current() != nil {
		t.Fatal("token swapped under the record used")
	}

	restore()
	if ks := newManager(t, dir, &now).Current(); ks == nil || ks.Version != 2 {
		t.Fatal("intact state not used")
	}
}

// A stored set that does not verify is not used, but the floor it recorded
// still refuses lower versions.
func TestUnusableStoreKeepsFloor(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if err := m.Offer(signSet(t, 5, "root-primary")); err != nil {
		t.Fatal(err)
	}
	// Only the backup root is pinned now: the primary-signed set is unusable.
	v := vectorKeys(t)
	m2, err := New(Config{Dir: dir, Roots: []ed25519.PublicKey{pub(t, v["root-backup"])}, AllowTestRoots: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Current() != nil {
		t.Fatal("unverifiable stored set used")
	}
	if err := m2.Offer(signSet(t, 4, "root-backup")); protocol.CodeOf(err) != protocol.CodeRollback {
		t.Fatalf("floor lost: %v", err)
	}
	if err := m2.Offer(signSet(t, 6, "root-backup")); err != nil {
		t.Fatal(err)
	}
}

func TestConfigRefusals(t *testing.T) {
	r := roots(t)
	now := func() time.Time { return t0 }
	if _, err := New(Config{Dir: stateDir(t), Now: now}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("no roots: %v", err)
	}
	if _, err := New(Config{Dir: stateDir(t), Roots: r, Now: now}); !errors.Is(err, ErrTestRoot) {
		t.Fatalf("test roots: %v", err)
	}
	if _, err := New(Config{Roots: r, AllowTestRoots: true, Now: now}); err == nil {
		t.Fatal("no folder accepted")
	}
	if _, err := New(Config{Dir: stateDir(t), Roots: []ed25519.PublicKey{make([]byte, 32)}, AllowTestRoots: true}); err == nil {
		t.Fatal("small-order root accepted")
	}
}

func TestParseRoots(t *testing.T) {
	v := vectorKeys(t)
	good := `{"roots":["` + v["root-primary"].X + `","` + v["root-backup"].X + `"]}`
	rs, err := ParseRoots([]byte(good))
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v %v", rs, err)
	}
	if rs, err := ParseRoots([]byte("  \n")); err != nil || rs != nil {
		t.Fatalf("empty: %v %v", rs, err)
	}
	for name, in := range map[string]string{
		"not json":   "{",
		"no roots":   `{"roots":[]}`,
		"unknown":    `{"roots":["` + v["root-primary"].X + `"],"x":1}`,
		"bad key":    `{"roots":["AAAA"]}`,
		"duplicate":  `{"roots":["` + v["root-primary"].X + `","` + v["root-primary"].X + `"]}`,
		"three":      `{"roots":["` + v["root-primary"].X + `","` + v["root-backup"].X + `","` + v["root-rogue"].X + `"]}`,
		"trailing":   good + "{}",
		"wrong type": `{"roots":"x"}`,
	} {
		if _, err := ParseRoots([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if b := Pinned(); strings.TrimSpace(string(b)) != string(b) {
		t.Fatal("pinned roots not trimmed")
	}
	if rs, err := ParseRoots(Pinned()); err != nil || rs != nil {
		t.Fatalf("production roots placeholder: %v %v", rs, err)
	}
}

func TestDigestRecorded(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	tok := signSet(t, 2, "root-primary")
	if err := m.Offer(tok); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(tok), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	want := sha256.Sum256(payload)
	if m.Status().Digest != hex.EncodeToString(want[:]) {
		t.Fatalf("digest %s", m.Status().Digest)
	}
}

// stateDir is a not yet existing private folder, as in the agent's data folder.
func stateDir(t *testing.T) string { return filepath.Join(t.TempDir(), "keyset") }

func TestVersionOneStored(t *testing.T) {
	dir := stateDir(t)
	now := t0
	if err := newManager(t, dir, &now).Offer(signSet(t, 1, "root-primary")); err != nil {
		t.Fatal(err)
	}
	if ks := newManager(t, dir, &now).Current(); ks == nil || ks.Version != 1 {
		t.Fatal("version 1 not reloaded")
	}
}

func TestTokenSHA256(t *testing.T) {
	now := t0
	m := newManager(t, stateDir(t), &now)
	if m.TokenSHA256() != "" {
		t.Fatal("hash without a key set")
	}
	tok := signSet(t, 2, "root-primary")
	if err := m.Offer(tok); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(tok)
	if m.TokenSHA256() != hex.EncodeToString(s[:]) {
		t.Fatal("hash is not over the accepted token bytes")
	}
}

func TestTUFFloorCopy(t *testing.T) {
	dir := stateDir(t)
	now := t0
	m := newManager(t, dir, &now)
	if m.TUFFloor() != (Floor{}) {
		t.Fatal("floor without a record")
	}
	f := Floor{Root: 2, Timestamp: 9, Snapshot: 7, Targets: 3}
	if err := m.SetTUFFloor(f); err != nil {
		t.Fatal(err)
	}
	if got := newManager(t, dir, &now).TUFFloor(); got != f {
		t.Fatalf("reloaded %+v", got)
	}
	info, err := os.Lstat(filepath.Join(dir, FloorFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
	// A recovery may lower it: the copy follows the verified state.
	low := Floor{Root: 3, Timestamp: 1, Snapshot: 1, Targets: 3}
	if err := m.SetTUFFloor(low); err != nil || m.TUFFloor() != low {
		t.Fatal("floor copy not replaced")
	}
	_ = os.WriteFile(filepath.Join(dir, FloorFile), []byte("{"), 0o600)
	if newManager(t, dir, &now).TUFFloor() != (Floor{}) {
		t.Fatal("corrupt floor copy used")
	}
	if err := (&Manager{}).SetTUFFloor(Floor{Root: -1}); err == nil {
		t.Fatal("negative floor accepted")
	}
}

func TestTUFFloorBounds(t *testing.T) {
	m := newManager(t, stateDir(t), &t0)
	if err := m.SetTUFFloor(Floor{}); err != nil {
		t.Fatalf("zero floor: %v", err)
	}
	for _, f := range []Floor{{Root: -1}, {Timestamp: -1}, {Snapshot: -1}, {Targets: -1}} {
		if err := m.SetTUFFloor(f); err == nil {
			t.Errorf("%+v accepted", f)
		}
	}
	dir := stateDir(t)
	_ = os.MkdirAll(dir, 0o700)
	for _, bad := range []string{`{"root":1,"extra":2}`, `{"root":-1}`} {
		_ = os.WriteFile(filepath.Join(dir, FloorFile), []byte(bad), 0o600)
		if newManager(t, dir, &t0).TUFFloor() != (Floor{}) {
			t.Errorf("%s used", bad)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, FloorFile), []byte(`{"root":4,"timestamp":3,"snapshot":2,"targets":1}`), 0o600)
	if got := newManager(t, dir, &t0).TUFFloor(); got != (Floor{Root: 4, Timestamp: 3, Snapshot: 2, Targets: 1}) {
		t.Fatalf("%+v", got)
	}
}
