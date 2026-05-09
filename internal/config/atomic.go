package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeAtomic writes data to path durably and atomically:
//   - Open a sibling temp file with the requested permissions
//   - Write the payload
//   - Fsync the file so the data hits the disk, not just the page cache
//   - Close, then rename the temp over the target (atomic on POSIX
//     filesystems for files within the same directory)
//   - Fsync the parent directory so the rename itself is durable
//
// On any failure the temp file is removed on a best-effort basis. This is
// the same pattern used by sqlite, etcd, BoltDB, and systemd: it's the
// minimum needed to survive a power loss without ending up with a
// truncated or vanished file.
//
// path must be an absolute path. The temp file lives next to it (same
// directory) so the rename never crosses filesystems.
func writeAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmpPath := path + ".tmp"

	// O_EXCL would be safer (prevent overwriting an abandoned tmp from a
	// previous crash) but it complicates recovery — we explicitly want to
	// reuse the slot. O_TRUNC ensures we don't append to stale content.
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) // #nosec G304
	if err != nil {
		return fmt.Errorf("open temp file: %w", err)
	}

	// Best-effort cleanup if anything below fails.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}

	// Fsync BEFORE close. The file's data must be on disk before we make
	// the directory entry point at it via rename; otherwise a crash
	// between rename and the data writeback leaves the new directory
	// entry pointing at zeroed/stale blocks.
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}

	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	// Fsync the parent directory so the rename itself is durable.
	// Failure here is logged via the returned error but we don't roll back
	// the rename — the data is already at the target path; we just lose
	// durability guarantees on the directory entry until the next sync.
	if err = fsyncDir(dir); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}

	return nil
}

// fsyncDir opens the directory and calls Sync on it. POSIX requires this
// to flush the directory entry. On platforms where directory fsync isn't
// meaningful (Windows), opening read-only and syncing is a no-op rather
// than an error in Go's stdlib, so the call is portable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
