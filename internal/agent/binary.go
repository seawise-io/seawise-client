package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func statBinary(path string) (fs.FileInfo, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("frpc path %q is not absolute", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("frpc %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("frpc %s is writable by others", path)
	}
	return fi, nil
}
