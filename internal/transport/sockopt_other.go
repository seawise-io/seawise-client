//go:build !linux

package transport

import "syscall"

func userTimeout(_, _ string, _ syscall.RawConn) error { return nil }
