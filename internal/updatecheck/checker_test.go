package updatecheck

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise/client/internal/tufrepo"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

const keysetV1 = `{"keys":["one"]}`

// fixture is a test TUF repository served over HTTPS. Individual paths can
// be overridden to simulate a hostile or broken mirror.
type fixture struct {
	t    *testing.T
	repo string
	keys *tufrepo.TestKeys
	srv  *httptest.Server

	mu       sync.Mutex
	now      time.Time
	override map[string]http.HandlerFunc
	hits     map[string]int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, repo: t.TempDir(), now: t0, override: map[string]http.HandlerFunc{}, hits: map[string]int{}}
	keys, err := tufrepo.InitTest(f.repo, t0)
	if err != nil {
		t.Fatal(err)
	}
	f.keys = keys
	f.publish(map[string][]byte{
		"release/stable.json": []byte(manifestJSON("stable", "2.1.0", "2031-01-01T00:00:00Z")),
		"keyset.json":         []byte(keysetV1),
	}, t0)
	files := http.FileServer(http.Dir(f.repo))
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		h := f.override[r.URL.Path]
		f.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// publish signs new targets and refreshes snapshot and timestamp at time at.
func (f *fixture) publish(add map[string][]byte, at time.Time) {
	f.t.Helper()
	if add != nil {
		if _, err := tufrepo.SignTargets(f.repo, f.keys.Targets, add, nil, at, tufrepo.DefaultTargetsExpiry); err != nil {
			f.t.Fatal(err)
		}
	}
	if _, err := tufrepo.Refresh(f.repo, f.keys.Snapshot, f.keys.Timestamp, at, tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) root() []byte {
	b, err := os.ReadFile(filepath.Join(f.repo, "metadata", "1.root.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) setNow(t time.Time) {
	f.mu.Lock()
	f.now = t
	f.mu.Unlock()
}

func (f *fixture) serve(path string, h http.HandlerFunc) {
	f.mu.Lock()
	f.override[path] = h
	f.mu.Unlock()
}

func (f *fixture) serveBytes(path string, b []byte) {
	f.serve(path, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(b) })
}

func (f *fixture) hit(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fixture) read(name string) []byte {
	b, err := os.ReadFile(filepath.Join(f.repo, "metadata", name))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) checker(stateDir string, mods ...func(*Config)) *Checker {
	f.t.Helper()
	cfg := Config{
		Root:          f.root(),
		AllowTestRoot: true,
		URL:           f.srv.URL,
		Dir:           stateDir,
		Channel:       "stable",
		Version:       "v2.0.0",
		Transport:     f.srv.Client().Transport,
		Now: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.now
		},
	}
	for _, m := range mods {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// stateDir is a not yet existing private folder, as in the agent's data folder.
func stateDir(t *testing.T) string { return filepath.Join(t.TempDir(), "tuf") }

func mustCheck(t *testing.T, c *Checker) {
	t.Helper()
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func signTimestamp(t *testing.T, ts *metadata.Metadata[metadata.TimestampType], keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	ts.ClearSignatures()
	for _, k := range keys {
		s, err := signature.LoadED25519Signer(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.Sign(s); err != nil {
			t.Fatal(err)
		}
	}
	b, err := ts.ToBytes(true)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidUpdate(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	if st := c.Status(); st.State != StatePending || st.Available != nil {
		t.Fatalf("before check: %+v", st)
	}
	mustCheck(t, c)
	st := c.Status()
	if st.State != StateOK || !st.Fresh || st.Available == nil || st.Available.Version != "2.1.0" || st.Available.Digest != goodDigest {
		t.Fatalf("status %+v", st)
	}
	if string(c.KeySet()) != keysetV1 {
		t.Fatalf("key set %q", c.KeySet())
	}
	sum := sha256.Sum256([]byte(keysetV1))
	if st.KeySetSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("key set hash not reported")
	}
	if !c.Fresh(t0.Add(13*24*time.Hour)) || c.Fresh(t0.Add(15*24*time.Hour)) {
		t.Fatal("fresh window does not follow the earliest expiry")
	}

	// Already on that version: no notice.
	c2 := f.checker(stateDir(t), func(cfg *Config) { cfg.Version = "v2.1.0" })
	mustCheck(t, c2)
	if c2.Status().Available != nil {
		t.Fatal("notice for the running version")
	}
	// A dev build never shows a notice.
	c3 := f.checker(stateDir(t), func(cfg *Config) { cfg.Version = "dev" })
	mustCheck(t, c3)
	if c3.Status().Available != nil {
		t.Fatal("notice for a dev build")
	}
	// No manifest for the beta channel: no notice, no error.
	c4 := f.checker(stateDir(t), func(cfg *Config) { cfg.Channel = "beta" })
	mustCheck(t, c4)
	if st := c4.Status(); st.State != StateOK || st.Available != nil {
		t.Fatalf("beta: %+v", st)
	}

	// Unchanged repository: the next check fetches only the timestamp.
	before := f.hit("/metadata/1.snapshot.json")
	mustCheck(t, c)
	if f.hit("/metadata/1.snapshot.json") != before {
		t.Fatal("unchanged snapshot fetched again")
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	mustCheck(t, f.checker(dir))
	c := f.checker(dir)
	if st := c.Status(); st.Available == nil || !st.Fresh || string(c.KeySet()) != keysetV1 {
		t.Fatalf("restored %+v", st)
	}
	for _, name := range []string{"state.json", "keyset.json"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", name, fi.Mode())
		}
	}
	// A key set that no longer matches its recorded hash is not used.
	if err := os.WriteFile(filepath.Join(dir, "keyset.json"), []byte(`{"keys":["evil"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ks := f.checker(dir).KeySet(); ks != nil {
		t.Fatalf("tampered key set loaded: %q", ks)
	}
}

func TestExpiredTimestamp(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	// The mirror stops refreshing (freeze); 15 days later the timestamp has expired.
	f.setNow(t0.Add(15 * 24 * time.Hour))
	err := c.Check(context.Background())
	var exp *metadata.ErrExpiredMetadata
	if !errors.As(err, &exp) {
		t.Fatalf("want expired, got %v", err)
	}
	st := c.Status()
	if st.State != StateExpired || st.Fresh || st.Available != nil {
		t.Fatalf("status %+v", st)
	}
	// The last verified key set stays in use so tunnels keep working.
	if string(c.KeySet()) != keysetV1 {
		t.Fatal("key set dropped on expiry")
	}
	// Once the repository is refreshed, everything is current again.
	f.publish(nil, t0.Add(15*24*time.Hour))
	mustCheck(t, c)
	if st := c.Status(); st.State != StateOK || !st.Fresh || st.Available == nil {
		t.Fatalf("after refresh %+v", st)
	}
}

func TestExpiredBeforeFirstCheck(t *testing.T) {
	f := newFixture(t)
	f.setNow(t0.Add(30 * 24 * time.Hour))
	c := f.checker(stateDir(t))
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("expired repository accepted")
	}
	if st := c.Status(); st.State != StateExpired || st.Fresh || c.KeySet() != nil {
		t.Fatalf("status %+v", st)
	}
}

func TestRollbackAttempt(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	c := f.checker(dir)
	mustCheck(t, c)
	oldTS := f.read("timestamp.json")
	f.publish(map[string][]byte{"release/stable.json": []byte(manifestJSON("stable", "2.2.0", "2031-01-01T00:00:00Z"))}, t0.Add(time.Hour))
	mustCheck(t, c)
	if v := c.Status().Available.Version; v != "2.2.0" {
		t.Fatalf("version %s", v)
	}

	// The mirror serves the older, still unexpired timestamp.
	f.serveBytes("/metadata/timestamp.json", oldTS)
	var bad *metadata.ErrBadVersionNumber
	if err := c.Check(context.Background()); !errors.As(err, &bad) {
		t.Fatalf("timestamp rollback: %v", err)
	}
	// Also after a restart: the floor is on disk.
	if err := f.checker(dir).Check(context.Background()); !errors.As(err, &bad) {
		t.Fatalf("timestamp rollback after restart: %v", err)
	}
	if v := c.Status().Available.Version; v != "2.2.0" {
		t.Fatalf("rollback changed the notice to %s", v)
	}

	// A newer timestamp that points at an older snapshot.
	ts, err := metadata.Timestamp().FromBytes(f.read("timestamp.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts.Signed.Version += 5
	ts.Signed.Meta["snapshot.json"] = metadata.MetaFile(1)
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp))
	if err := c.Check(context.Background()); !errors.As(err, &bad) {
		t.Fatalf("snapshot rollback: %v", err)
	}
}

func TestMixAndMatch(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	oldSnap := f.read("1.snapshot.json")
	oldTargets := f.read("2.targets.json")
	f.publish(map[string][]byte{"release/stable.json": []byte(manifestJSON("stable", "2.2.0", "2031-01-01T00:00:00Z"))}, t0.Add(time.Hour))

	// Snapshot from an older state under the new name.
	f.serveBytes("/metadata/2.snapshot.json", oldSnap)
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("old snapshot accepted under a new version")
	}
	f.serve("/metadata/2.snapshot.json", nil)

	// Targets from an older state under the new name.
	f.serveBytes("/metadata/3.targets.json", oldTargets)
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("old targets accepted under a new version")
	}
	if v := c.Status().Available.Version; v != "2.1.0" {
		t.Fatalf("mixed state changed the notice to %s", v)
	}
	f.serve("/metadata/3.targets.json", nil)
	mustCheck(t, c)
	if v := c.Status().Available.Version; v != "2.2.0" {
		t.Fatalf("version %s", v)
	}
}

func TestWrongKeyAndThreshold(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	ts, err := metadata.Timestamp().FromBytes(f.read("timestamp.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts.Signed.Version++
	var unsigned *metadata.ErrUnsignedMetadata
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Snapshot))
	if err := c.Check(context.Background()); !errors.As(err, &unsigned) {
		t.Fatalf("timestamp signed by the snapshot key: %v", err)
	}
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts))
	if err := c.Check(context.Background()); !errors.As(err, &unsigned) {
		t.Fatalf("unsigned timestamp: %v", err)
	}

	// The timestamp role now needs two of two keys; one signature is not enough.
	f.serve("/metadata/timestamp.json", nil)
	second, _ := tufrepo.GenerateKey()
	if _, err := tufrepo.RotateRoot(f.repo, tufrepo.RootChange{
		Roles: map[string]tufrepo.RoleKeys{metadata.TIMESTAMP: {Keys: []ed25519.PublicKey{
			f.keys.Timestamp.Public().(ed25519.PublicKey), second.Public().(ed25519.PublicKey)}, Threshold: 2}},
		Signers: []ed25519.PrivateKey{f.keys.RootPrimary}, Now: t0, Expires: tufrepo.DefaultRootExpiry,
	}); err != nil {
		t.Fatal(err)
	}
	ts.Signed.Version++
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp))
	if err := c.Check(context.Background()); !errors.As(err, &unsigned) {
		t.Fatalf("one of two timestamp signatures: %v", err)
	}
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp, second))
	mustCheck(t, c)
}

func TestRootRotation(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	c := f.checker(dir)
	mustCheck(t, c)

	// The primary root key is lost: the backup root key signs a new root
	// that replaces it and rotates the timestamp key.
	newPrimary, _ := tufrepo.GenerateKey()
	newTS, _ := tufrepo.GenerateKey()
	if _, err := tufrepo.RotateRoot(f.repo, tufrepo.RootChange{
		Roles: map[string]tufrepo.RoleKeys{
			metadata.ROOT:      {Keys: []ed25519.PublicKey{newPrimary.Public().(ed25519.PublicKey), f.keys.RootBackup.Public().(ed25519.PublicKey)}, Threshold: 1},
			metadata.TIMESTAMP: {Keys: []ed25519.PublicKey{newTS.Public().(ed25519.PublicKey)}, Threshold: 1},
		},
		Signers: []ed25519.PrivateKey{f.keys.RootBackup}, Now: t0, Expires: tufrepo.DefaultRootExpiry,
	}); err != nil {
		t.Fatal(err)
	}
	oldTSBytes := f.read("timestamp.json")
	if _, err := tufrepo.Refresh(f.repo, f.keys.Snapshot, newTS, t0.Add(time.Hour), tufrepo.DefaultOnlineExpiry, tufrepo.DefaultMinRemaining); err != nil {
		t.Fatal(err)
	}
	mustCheck(t, c)
	if st := c.Status(); st.State != StateOK {
		t.Fatalf("after rotation %+v", st)
	}

	// The old timestamp key no longer counts.
	ts, _ := metadata.Timestamp().FromBytes(oldTSBytes)
	ts.Signed.Version = 10
	f.serveBytes("/metadata/timestamp.json", signTimestamp(t, ts, f.keys.Timestamp))
	var unsigned *metadata.ErrUnsignedMetadata
	if err := c.Check(context.Background()); !errors.As(err, &unsigned) {
		t.Fatalf("old timestamp key after rotation: %v", err)
	}
	f.serve("/metadata/timestamp.json", nil)

	// A restarted agent starts from the rotated root on disk, not the
	// older pinned one.
	before := f.hit("/metadata/2.root.json")
	c2 := f.checker(dir)
	mustCheck(t, c2)
	if f.hit("/metadata/2.root.json") != before {
		t.Fatal("restarted agent fetched 2.root.json again")
	}

	// A root signed only by keys the current root does not trust.
	evil1, _ := tufrepo.GenerateKey()
	evil2, _ := tufrepo.GenerateKey()
	r, _ := metadata.Root().FromBytes(f.read("2.root.json"))
	r.ClearSignatures()
	r.Signed.Version = 3
	for _, k := range []ed25519.PrivateKey{evil1, evil2} {
		tk, _ := metadata.KeyFromPublicKey(k.Public())
		id, _ := tk.ID()
		r.Signed.Keys[id] = tk
	}
	ids := []string{}
	for _, k := range []ed25519.PrivateKey{evil1, evil2} {
		id, _ := tufrepo.KeyID(k.Public().(ed25519.PublicKey))
		ids = append(ids, id)
	}
	r.Signed.Roles[metadata.ROOT] = &metadata.Role{KeyIDs: ids, Threshold: 1}
	s, _ := signature.LoadED25519Signer(evil1)
	if _, err := r.Sign(s); err != nil {
		t.Fatal(err)
	}
	rb, _ := r.ToBytes(true)
	f.serveBytes("/metadata/3.root.json", rb)
	if err := c2.Check(context.Background()); !errors.As(err, &unsigned) {
		t.Fatalf("root signed by untrusted keys: %v", err)
	}
}

func TestEndlessData(t *testing.T) {
	f := newFixture(t)
	f.serve("/metadata/timestamp.json", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32<<10)
		for r.Context().Err() == nil {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	})
	c := f.checker(stateDir(t))
	start := time.Now()
	err := c.Check(context.Background())
	var lm *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &lm) {
		t.Fatalf("endless timestamp: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("endless data not cut off quickly")
	}
	if st := c.Status(); st.State != StateError || st.Fresh {
		t.Fatalf("status %+v", st)
	}
}

func TestOversizedMetadata(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	f.publish(map[string][]byte{"keyset.json": []byte(`{"keys":["two"]}`)}, t0.Add(time.Hour))

	// Targets metadata padded beyond the length the snapshot signs.
	padded := append(f.read("3.targets.json"), []byte(strings.Repeat(" ", 4096))...)
	f.serveBytes("/metadata/3.targets.json", padded)
	var lm *metadata.ErrDownloadLengthMismatch
	if err := c.Check(context.Background()); !errors.As(err, &lm) {
		t.Fatalf("padded targets: %v", err)
	}
	f.serve("/metadata/3.targets.json", nil)

	// A root larger than the cap.
	f.serveBytes("/metadata/2.root.json", make([]byte, maxRootSize+1))
	if err := c.Check(context.Background()); !errors.As(err, &lm) {
		t.Fatalf("oversized root: %v", err)
	}
	f.serve("/metadata/2.root.json", nil)
	mustCheck(t, c)
}

func TestOversizedTarget(t *testing.T) {
	f := newFixture(t)
	big := []byte(manifestJSON("stable", "2.2.0", "2031-01-01T00:00:00Z"))
	big = append(big[:len(big)-1], []byte(`,"notes":"`+strings.Repeat("x", maxReleaseSize)+`"}`)...)
	f.publish(map[string][]byte{"release/stable.json": big}, t0.Add(time.Hour))
	c := f.checker(stateDir(t))
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized target: %v", err)
	}
	f.mu.Lock()
	for p, n := range f.hits {
		if strings.HasSuffix(p, ".stable.json") && n > 0 {
			t.Errorf("oversized target was downloaded: %s", p)
		}
	}
	f.mu.Unlock()
	// The key set is still verified and kept.
	if string(c.KeySet()) != keysetV1 {
		t.Fatal("key set lost because of the release manifest")
	}
}

func TestSlowRetrieval(t *testing.T) {
	f := newFixture(t)
	f.serve("/metadata/timestamp.json", func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for i := 0; i < 1000 && r.Context().Err() == nil; i++ {
			_, _ = w.Write([]byte(" "))
			fl.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})
	c := f.checker(stateDir(t), func(cfg *Config) { cfg.RequestTimeout = 300 * time.Millisecond })
	start := time.Now()
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("slow retrieval accepted")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("slow retrieval took %v", d)
	}
	// The whole check is bounded too, whatever the per-request limit.
	c2 := f.checker(stateDir(t), func(cfg *Config) { cfg.RequestTimeout = time.Hour; cfg.CheckTimeout = 400 * time.Millisecond })
	start = time.Now()
	if err := c2.Check(context.Background()); err == nil {
		t.Fatal("slow retrieval accepted")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("check took %v", d)
	}
}

func TestRedirectRefused(t *testing.T) {
	f := newFixture(t)
	f.serve("/metadata/timestamp.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/metadata/1.snapshot.json", http.StatusFound)
	})
	c := f.checker(stateDir(t))
	var he *metadata.ErrDownloadHTTP
	if err := c.Check(context.Background()); !errors.As(err, &he) || he.StatusCode != http.StatusFound {
		t.Fatalf("redirect: %v", err)
	}
}

func TestConfigRefusals(t *testing.T) {
	f := newFixture(t)
	base := func() Config {
		return Config{Root: f.root(), AllowTestRoot: true, URL: f.srv.URL, Dir: stateDir(t), Channel: "stable", Version: "v2.0.0"}
	}
	cases := map[string]func(*Config){
		"empty root":   func(c *Config) { c.Root = nil },
		"empty url":    func(c *Config) { c.URL = "" },
		"http":         func(c *Config) { c.URL = "http://example.com" },
		"query":        func(c *Config) { c.URL = f.srv.URL + "/?x=1" },
		"channel":      func(c *Config) { c.Channel = "nightly" },
		"no dir":       func(c *Config) { c.Dir = "" },
		"test root":    func(c *Config) { c.AllowTestRoot = false },
		"garbage root": func(c *Config) { c.Root = []byte("{}") },
	}
	for name, mod := range cases {
		cfg := base()
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	cfg := base()
	cfg.Root = nil
	if _, err := New(cfg); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("empty root: %v", err)
	}
	cfg = base()
	cfg.AllowTestRoot = false
	if _, err := New(cfg); !errors.Is(err, ErrTestRoot) {
		t.Errorf("test root: %v", err)
	}

	// A pinned root with a single root key has no backup.
	k, _ := tufrepo.GenerateKey()
	one := tufrepo.RoleKeys{Keys: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Threshold: 1}
	r := metadata.Root(t0.Add(time.Hour))
	tk, _ := metadata.KeyFromPublicKey(k.Public())
	id, _ := tk.ID()
	r.Signed.Keys[id] = tk
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		r.Signed.Roles[role] = &metadata.Role{KeyIDs: []string{id}, Threshold: one.Threshold}
	}
	s, _ := signature.LoadED25519Signer(k)
	_, _ = r.Sign(s)
	rb, _ := r.ToBytes(false)
	cfg = base()
	cfg.Root = rb
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "backup") {
		t.Errorf("single root key: %v", err)
	}
}

func TestProductionRootPlaceholder(t *testing.T) {
	root, url := Pinned()
	if len(root) != 0 || url != "" {
		t.Skip("production root is set")
	}
	_, err := New(Config{Root: root, URL: url, Dir: t.TempDir(), Channel: "stable"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("placeholder: %v", err)
	}
}

func TestDiskRootSelection(t *testing.T) {
	f := newFixture(t)
	dir := stateDir(t)
	mustCheck(t, f.checker(dir))
	if _, err := tufrepo.RotateRoot(f.repo, tufrepo.RootChange{Signers: []ed25519.PrivateKey{f.keys.RootPrimary}, Now: t0, Expires: tufrepo.DefaultRootExpiry}); err != nil {
		t.Fatal(err)
	}
	mustCheck(t, f.checker(dir))

	// A disk root that is not self-signed is ignored in favour of the pinned root.
	onDisk := filepath.Join(dir, "metadata", "root.json")
	r, _ := metadata.Root().FromBytes(f.read("2.root.json"))
	r.Signed.Version = 9
	rb, _ := r.ToBytes(true)
	if err := os.WriteFile(onDisk, rb, 0o600); err != nil {
		t.Fatal(err)
	}
	c := f.checker(dir)
	if got, _ := c.trustedRoot(); !strings.Contains(string(got), `"version": 1`) {
		t.Fatalf("unsigned disk root used:\n%s", got)
	}
	mustCheck(t, c)
}

func TestRunSchedules(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t), func(cfg *Config) {
		cfg.FirstDelay = time.Millisecond
		cfg.Interval = time.Hour
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for c.Status().State == StatePending && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if st := c.Status(); st.State != StateOK {
		t.Fatalf("run: %+v", st)
	}
}

func TestStatusError(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	f.serve("/metadata/timestamp.json", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) })
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("503 accepted")
	}
	st := c.Status()
	// A mirror outage does not hide a still-fresh verified notice.
	if st.State != StateError || st.Error == "" || st.Available == nil || !st.Fresh {
		t.Fatalf("status %+v", st)
	}
	if strings.Contains(st.Error, f.srv.URL) {
		t.Fatalf("error leaks the URL: %s", st.Error)
	}
}
