//go:build unix

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// checkBinary refuses an frpc binary that is not an absolute path to a
// regular file owned by root or this user and not writable by others.
func checkBinary(path string) error {
	fi, err := statBinary(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("frpc %s: no ownership data", path)
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("frpc %s is owned by uid %d", path, st.Uid)
	}
	return nil
}
