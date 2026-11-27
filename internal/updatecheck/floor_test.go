package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// The platform's fixture repository (written by tufrepo with fixed seeds)
// and the go-tuf verdicts on it; client and platform must agree.
const fixtureRepo = "../../testdata/tuf-repo"

type platformRepo struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	state string
	now   time.Time
}

func newPlatformRepo(t *testing.T, state string, at time.Time) *platformRepo {
	t.Helper()
	p := &platformRepo{t: t, state: state, now: at}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		dir := filepath.Join(fixtureRepo, "states", p.state)
		p.mu.Unlock()
		http.FileServer(http.Dir(dir)).ServeHTTP(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *platformRepo) set(state string, at time.Time) {
	p.mu.Lock()
	p.state, p.now = state, at
	p.mu.Unlock()
}

func (p *platformRepo) pinned() []byte {
	b, err := os.ReadFile(filepath.Join(fixtureRepo, "states", "A", "metadata", "1.root.json"))
	if err != nil {
		p.t.Fatal(err)
	}
	return b
}

func (p *platformRepo) checker(dir string, mods ...func(*Config)) *Checker {
	p.t.Helper()
	cfg := Config{
		Root: p.pinned(), AllowTestRoot: true, URL: p.srv.URL, Dir: dir, Channel: "stable", Version: "v2.0.0",
		Transport: p.srv.Client().Transport,
		Now: func() time.Time {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.now
		},
	}
	for _, m := range mods {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		p.t.Fatal(err)
	}
	return c
}

type verdict struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Floor  string `json:"floor"`
	At     string `json:"at"`
	Expect string `json:"expect"`
}

func TestPlatformVerdicts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureRepo, "verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []verdict
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 8 {
		t.Fatalf("%d verdicts", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, v.At)
			if err != nil {
				t.Fatal(err)
			}
			dir := stateDir(t)
			p := newPlatformRepo(t, v.State, at)
			if v.Floor != "" {
				p.set(v.Floor, at)
				mustCheck(t, p.checker(dir))
				p.set(v.State, at)
			}
			err = p.checker(dir).Check(context.Background())
			if (err == nil) != (v.Expect == "ok") {
				t.Fatalf("expect %s, got %v", v.Expect, err)
			}
		})
	}
}

var atE = time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)

// A host that omits the newer root must not lower the trusted state, even
// when the stored metadata is gone and only the sealed record is left.
func TestFloorSurvivesOmittedRoot(t *testing.T) {
	dir := stateDir(t)
	p := newPlatformRepo(t, "E", atE)
	mustCheck(t, p.checker(dir))

	p.set("D", atE)
	var bad *metadata.ErrBadVersionNumber
	if err := p.checker(dir).Check(context.Background()); err == nil {
		t.Fatal("state D accepted over floor E")
	}
	for _, name := range []string{"root.json", "timestamp.json", "snapshot.json", "targets.json"} {
		_ = os.Remove(filepath.Join(dir, "metadata", name))
	}
	if err := p.checker(dir).Check(context.Background()); !errors.As(err, &bad) {
		t.Fatalf("floor lost with the stored files: %v", err)
	}
	// E is still accepted, so the floor never blocks the real repository.
	p.set("E", atE)
	mustCheck(t, p.checker(dir))
}

func TestStoredRootStartsTheChain(t *testing.T) {
	dir := stateDir(t)
	p := newPlatformRepo(t, "E", atE)
	mustCheck(t, p.checker(dir))
	b, err := os.ReadFile(filepath.Join(dir, "metadata", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := metadata.Root().FromBytes(b)
	if err != nil || r.Signed.Version != 2 {
		t.Fatalf("stored root %v %v", r, err)
	}
	// An edited stored root does not match the sealed record and is not
	// used; the chain starts again from the pinned root.
	if err := os.WriteFile(filepath.Join(dir, "metadata", "root.json"), append(b, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	mustCheck(t, p.checker(dir))
}

func TestStoredFilesArePrivate(t *testing.T) {
	dir := stateDir(t)
	p := newPlatformRepo(t, "E", atE)
	mustCheck(t, p.checker(dir))
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s is a symlink", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v", path, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A symlinked stored file is not followed: the floor still holds.
	ts := filepath.Join(dir, "metadata", "timestamp.json")
	elsewhere := filepath.Join(t.TempDir(), "timestamp.json")
	b, _ := os.ReadFile(ts)
	_ = os.WriteFile(elsewhere, b, 0o600)
	_ = os.Remove(ts)
	if err := os.Symlink(elsewhere, ts); err != nil {
		t.Fatal(err)
	}
	p.set("D", atE)
	if err := p.checker(dir).Check(context.Background()); err == nil {
		t.Fatal("rollback accepted with a symlinked timestamp")
	}
}

func TestKeySetHandedOver(t *testing.T) {
	dir := stateDir(t)
	p := newPlatformRepo(t, "E", atE)
	var got []byte
	c := p.checker(dir, func(c *Config) {
		c.OnKeySet = func(b []byte) { got = b }
	})
	mustCheck(t, c)
	want, err := os.ReadFile(filepath.Join(fixtureRepo, "keyset-v6.jws"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("key set %q", got)
	}
	// A failed check hands nothing over.
	got = nil
	p.set("E", atE.Add(30*24*time.Hour))
	if err := c.Check(context.Background()); err == nil || got != nil {
		t.Fatalf("expired check: %v, key set %q", err, got)
	}
}

func mustFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStartRootChoice(t *testing.T) {
	dir := stateDir(t)
	p := newPlatformRepo(t, "E", atE)
	c := p.checker(dir)
	v1 := mustFile(t, filepath.Join(fixtureRepo, "states", "E", "metadata", "1.root.json"))
	v2 := mustFile(t, filepath.Join(fixtureRepo, "states", "E", "metadata", "2.root.json"))
	if err := mkdirPrivate(filepath.Join(dir, metaDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.metaPath("root.json"), v2, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.startRoot(sum(v2)); string(got) != string(v2) {
		t.Fatal("recorded stored root not used")
	}
	if got := c.startRoot(""); string(got) != string(c.cfg.Root) {
		t.Fatal("stored root used without a record")
	}
	if got := c.startRoot(sum(v1)); string(got) != string(c.cfg.Root) {
		t.Fatal("stored root used with another record")
	}
	c.cfg.AllowTestRoot = false
	if got := c.startRoot(sum(v2)); string(got) != string(c.cfg.Root) {
		t.Fatal("stored test root used")
	}
	c.cfg.AllowTestRoot = true
	c.cfg.Root = v2
	_ = os.Remove(c.metaPath("root.json"))
	if err := os.WriteFile(c.metaPath("root.json"), v1, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.startRoot(sum(v1)); string(got) != string(v2) {
		t.Fatal("stored root older than the pinned one used")
	}
}
