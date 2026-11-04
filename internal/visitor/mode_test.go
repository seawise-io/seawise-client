package visitor

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// modeDir is a fresh server folder, 0700 as the agent creates it.
func modeDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "srv")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openMode(t *testing.T, dir string) (*ModeStore, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	m, err := OpenMode(dir, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return m, &logs
}

func TestModeDefaultsToObserve(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "visitor", "srv")
	m, _ := openMode(t, dir)
	if m.Mode() != Observe {
		t.Fatal(m.Mode())
	}
	if st := m.Status(); st != (ModeStatus{Mode: Observe}) {
		t.Fatalf("%+v", st)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("folder: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ModeFile)); !os.IsNotExist(err) {
		t.Fatal("opening wrote a file")
	}
}

func TestModeSetPersistsAndOrders(t *testing.T) {
	dir := modeDir(t)
	m, _ := openMode(t, dir)
	if changed, err := m.Set(Enforce, 1000); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if m.Mode() != Enforce {
		t.Fatal("not enforcing")
	}
	fi, err := os.Stat(filepath.Join(dir, ModeFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", fi, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ModeFile))
	if string(b) != `{"schema":1,"mode":"enforce","seq":1000}` {
		t.Fatalf("file %s", b)
	}
	// An instruction with a seq at or below the stored one changes nothing.
	for _, at := range []int64{999, 1000} {
		if changed, err := m.Set(Observe, at); err != nil || changed {
			t.Fatal(at, changed, err)
		}
	}
	if m.Mode() != Enforce {
		t.Fatal("older instruction applied")
	}
	m2, _ := openMode(t, dir)
	if m2.Mode() != Enforce || m2.Status().Seq != 1000 {
		t.Fatalf("reopen: %+v", m2.Status())
	}
	if changed, err := m2.Set(Observe, 1001); err != nil || !changed || m2.Mode() != Observe {
		t.Fatal(changed, err)
	}
	m3, _ := openMode(t, dir)
	if m3.Mode() != Observe || m3.Status().Seq != 1001 {
		t.Fatalf("reopen: %+v", m3.Status())
	}
}

func TestModeSetRefusesUnknownMode(t *testing.T) {
	m, _ := openMode(t, modeDir(t))
	for _, mode := range []Mode{"", "ENFORCE", "strict"} {
		if _, err := m.Set(mode, 5); err == nil {
			t.Fatalf("%q accepted", mode)
		}
	}
	if _, err := m.Set(Enforce, -1); err == nil {
		t.Fatal("negative seq accepted")
	}
	if _, err := m.Set(Enforce, 0); err == nil {
		t.Fatal("seq 0 accepted")
	}
	if m.Mode() != Observe || m.Status().Seq != 0 {
		t.Fatal("state changed")
	}
}

func TestModeFileAtSeqZero(t *testing.T) {
	dir := modeDir(t)
	if err := os.WriteFile(filepath.Join(dir, ModeFile), []byte(`{"schema":1,"mode":"enforce","seq":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := openMode(t, dir)
	if m.Mode() != Enforce || m.Status().Error != "" {
		t.Fatalf("%+v", m.Status())
	}
}

func TestModeUnreadableFileIsObserve(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":     "not json",
		"unknown":     `{"schema":1,"mode":"strict","seq":1}`,
		"schema":      `{"schema":2,"mode":"enforce","seq":1}`,
		"extra":       `{"schema":1,"mode":"enforce","seq":1,"x":1}`,
		"negative":    `{"schema":1,"mode":"enforce","seq":-1}`,
		"trailing":    `{"schema":1,"mode":"enforce","seq":1}{}`,
		"empty":       ``,
		"mode absent": `{"schema":1,"seq":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := modeDir(t)
			if err := os.WriteFile(filepath.Join(dir, ModeFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			m, logs := openMode(t, dir)
			st := m.Status()
			if m.Mode() != Observe || st.Error == "" || st.Mode != Observe {
				t.Fatalf("%+v", st)
			}
			if !strings.Contains(logs.String(), "observe") {
				t.Fatalf("not logged: %s", logs)
			}
			// The next instruction rewrites it.
			if changed, err := m.Set(Enforce, 10); err != nil || !changed || m.Status().Error != "" {
				t.Fatal(changed, err, m.Status())
			}
			m2, _ := openMode(t, dir)
			if m2.Mode() != Enforce {
				t.Fatal("not rewritten")
			}
		})
	}
}

func TestModeFileOwnershipChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	t.Run("world readable", func(t *testing.T) {
		dir := modeDir(t)
		p := filepath.Join(dir, ModeFile)
		if err := os.WriteFile(p, []byte(`{"schema":1,"mode":"enforce","seq":1}`), 0o644); err != nil {
			t.Fatal(err)
		}
		m, _ := openMode(t, dir)
		if m.Mode() != Observe || m.Status().Error == "" {
			t.Fatalf("%+v", m.Status())
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := modeDir(t)
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(target, []byte(`{"schema":1,"mode":"enforce","seq":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, ModeFile)); err != nil {
			t.Fatal(err)
		}
		m, _ := openMode(t, dir)
		if m.Mode() != Observe || m.Status().Error == "" {
			t.Fatalf("%+v", m.Status())
		}
	})
	t.Run("open folder", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenMode(dir, nil); err == nil {
			t.Fatal("world-writable folder accepted")
		}
	})
}

func TestModeStoreFeedsTheGate(t *testing.T) {
	m, _ := openMode(t, modeDir(t))
	f := newFixture(t)
	g, err := New(Config{KeySet: f.gate.cfg.KeySet, Mode: m.Mode, Now: f.gate.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	if d := g.Check(Request{AppID: appA}); !d.Allow {
		t.Fatal("observe refused")
	}
	if _, err := m.Set(Enforce, 1); err != nil {
		t.Fatal(err)
	}
	if d := g.Check(Request{AppID: appA}); d.Allow || d.Mode != Enforce {
		t.Fatalf("%+v", d)
	}
}
