//go:build linux

package transport

import (
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// userTimeout sets TCP_USER_TIMEOUT, so unacknowledged data ends the
// connection instead of keepalive probes.
func userTimeout(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(TCPUserTimeout/time.Millisecond)) //nolint:gosec // G115: a socket descriptor
	})
	if err != nil {
		return err
	}
	return serr
}
