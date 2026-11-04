package testedge

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func readTCPInfo(c net.Conn) (Sample, bool) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return Sample{}, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return Sample{}, false
	}
	var info *unix.TCPInfo
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		info, gerr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || gerr != nil {
		return Sample{}, false
	}
	return Sample{At: time.Now(), Sent: info.Bytes_sent, Recv: info.Bytes_received,
		SegsIn: uint64(info.Segs_in), SegsOut: uint64(info.Segs_out)}, true
}
