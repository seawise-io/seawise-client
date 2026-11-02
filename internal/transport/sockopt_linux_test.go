//go:build linux

package transport

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDefaultSocketOptions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d, err := New(Config{Edges: func() *EdgeList { return edgeList(t) }, Key: seedKey("device"), ServerID: testServer,
		RunID: [16]byte{1}, AgentVersion: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.dialTCP(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, _ := c.(*net.TCPConn).SyscallConn()
	var timeout, keepalive int
	_ = rc.Control(func(fd uintptr) {
		timeout, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
		keepalive, _ = unix.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	})
	if timeout != 25000 || keepalive != 0 {
		t.Fatal(timeout, keepalive)
	}
}
