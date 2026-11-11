package session

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// watchNetlink subscribes to rtnetlink link, address and route groups on a
// non-blocking socket, so closing it ends the reader.
func watchNetlink(ctx context.Context, ch chan<- struct{}, log *slog.Logger) bool {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		log.Info("netlink unavailable; polling interfaces for network changes", "error", err)
		return false
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		log.Info("netlink unavailable; polling interfaces for network changes", "error", err)
		return false
	}
	f := os.NewFile(uintptr(fd), "netlink")
	context.AfterFunc(ctx, func() { _ = f.Close() })
	go func() {
		buf := make([]byte, 16<<10)
		for {
			n, err := f.Read(buf)
			if errors.Is(err, unix.ENOBUFS) {
				notify(ch)
				continue
			}
			if err != nil {
				if ctx.Err() == nil {
					log.Warn("netlink watcher stopped; polling interfaces", "error", err)
					go pollInterfaces(ctx, ch, PollEvery, interfaceFingerprint)
				}
				return
			}
			if n > 0 {
				notify(ch)
			}
		}
	}()
	return true
}
