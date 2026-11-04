package updatecheck

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// memRepo serves a fixture state from memory with some files replaced.
type memRepo struct {
	files map[string][]byte
}

func (m memRepo) DownloadFile(u string, maxLength int64, _ time.Duration) ([]byte, error) {
	i := strings.Index(u, "/metadata/")
	if i < 0 {
		i = strings.Index(u, "/targets/")
	}
	b, ok := m.files[u[i+1:]]
	if !ok {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: http.StatusNotFound, URL: u}
	}
	if int64(len(b)) > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: "too large"}
	}
	return b, nil
}

func loadState(t testing.TB, state string) map[string][]byte {
	files := map[string][]byte{}
	root := filepath.Join(fixtureRepo, "states", state)
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(root, p)
		files[filepath.ToSlash(rel)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// FuzzMetadataIntake serves state E with one top-level document replaced
// by arbitrary bytes, as stored or as fetched. Nothing may panic, and a
// verified result never falls below the floor of state E.
func FuzzMetadataIntake(f *testing.F) {
	e := loadState(f, "E")
	for _, name := range []string{"metadata/timestamp.json", "metadata/3.snapshot.json", "metadata/3.targets.json", "metadata/2.root.json"} {
		f.Add(uint8(0), e[name])
		f.Add(uint8(1), e[name])
	}
	f.Add(uint8(2), []byte(`{"signed":{},"signatures":[]}`))
	names := []string{"metadata/timestamp.json", "metadata/3.snapshot.json", "metadata/3.targets.json", "metadata/2.root.json", "metadata/3.root.json"}
	stored := []string{"timestamp.json", "snapshot.json", "targets.json", "root.json"}
	pinned := e["metadata/1.root.json"]
	floor := Versions{Root: 2, Timestamp: 4, Snapshot: 3, Targets: 3}
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		dir := filepath.Join(t.TempDir(), "tuf")
		c, err := New(Config{Root: pinned, AllowTestRoot: true, URL: "https://repo.invalid", Dir: dir, Channel: "stable", Version: "v2.0.0"})
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		for k, v := range e {
			files[k] = v
		}
		rootSum := ""
		if which%2 == 0 {
			files[names[int(which/2)%len(names)]] = data
		} else {
			if err := mkdirPrivate(filepath.Join(dir, metaDir)); err != nil {
				t.Fatal(err)
			}
			name := stored[int(which/2)%len(stored)]
			if err := os.WriteFile(c.metaPath(name), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if name == "root.json" {
				rootSum = sum(data)
			}
		}
		repo, err := c.refresh(memRepo{files}, atE, floor, rootSum)
		if err != nil {
			return
		}
		v := repo.versions
		if v.Root < floor.Root || v.Timestamp < floor.Timestamp || v.Snapshot < floor.Snapshot || v.Targets < floor.Targets {
			t.Fatalf("verified %+v below the floor", v)
		}
	})
}
