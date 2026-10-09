package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotDurable means the new content is in place but the directory fsync
// failed, so the rename may not survive a power loss.
var ErrNotDurable = errors.New("written, directory not synced")

// failpoint lets tests stop a write at a named step.
var failpoint = func(step string) error { return nil }

const tmpMarker = ".tmp-"

// WriteFileAtomic replaces path with data so that a crash leaves either the
// old or the new content, never a mix: temp file, fsync, rename, dir fsync.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if err := failpoint("create"); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+base+tmpMarker+"*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()
	closed := false
	defer func() {
		if err != nil {
			if !closed {
				_ = f.Close()
			}
			_ = os.Remove(tmp)
		}
	}()

	if err = failpoint("chmod"); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err = failpoint("write"); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err = failpoint("sync"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err = failpoint("close"); err != nil {
		return err
	}
	closed = true
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err = failpoint("rename"); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// The new content is in place from here on.
	if derr := failpoint("dirsync"); derr != nil {
		return fmt.Errorf("%w: %v", ErrNotDurable, derr)
	}
	if derr := syncDir(dir); derr != nil {
		return fmt.Errorf("%w: %v", ErrNotDurable, derr)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// removeStaleTemps deletes temp files left by an interrupted write.
func removeStaleTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), tmpMarker) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
