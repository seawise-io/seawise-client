//go:build unix

package legacy

import "syscall"

const readOnlyFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
