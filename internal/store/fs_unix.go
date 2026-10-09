//go:build unix

package store

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

var euid = os.Geteuid

const maxFileSize = 16 << 20

// checkOwned refuses entries that another user owns or that group or
// others can access.
func checkOwned(info fs.FileInfo, path string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: no ownership data", ErrUnsafePath, path)
	}
	if int(st.Uid) != euid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrUnsafePath, path, st.Uid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %v, want no group or other access", ErrUnsafePath, path, info.Mode().Perm())
	}
	return nil
}

func checkDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, path)
	}
	return checkOwned(info, path)
}

// openOwned opens path without following symlinks and checks the opened
// handle, so a swap after the check cannot redirect the read.
func openOwned(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0o600)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafePath, path)
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	if err := checkOwned(info, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// OpenOwned opens a file in the store directory with the same checks as
// the store's own files: no symlinks, regular file, owned by this user and
// not accessible to group or others. New files are created with mode 0600.
func OpenOwned(path string, flag int) (*os.File, error) { return openOwned(path, flag) }

func readOwned(path string) ([]byte, error) {
	f, err := openOwned(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("%w: %s too large", ErrUnsafePath, path)
	}
	return b, nil
}

func lockDir(dir string) (*os.File, error) {
	path := dir + string(os.PathSeparator) + LockFile
	f, err := openOwned(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, dir)
		}
		return nil, err
	}
	return f, nil
}
