//go:build !unix

package store

import (
	"fmt"
	"io"
	"os"
)

var euid = os.Geteuid

const maxFileSize = 16 << 20

func checkDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, path)
	}
	return nil
}

func readOwned(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxFileSize))
}

func OpenOwned(path string, flag int) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	return os.OpenFile(path, flag, 0o600)
}

func lockDir(dir string) (*os.File, error) {
	return nil, fmt.Errorf("%w: locking not supported on this platform", ErrLocked)
}
