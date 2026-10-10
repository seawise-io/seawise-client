package adminui

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestIsTLSClientHello(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want bool
	}{
		{[]byte{0x16, 0x03, 0x01}, true},
		{[]byte{0x16, 0x03, 0x03, 0x00}, true},
		{[]byte{0x16, 0x03, 0x05}, false},
		{[]byte{0x16, 0x02, 0x01}, false},
		{[]byte("GET"), false},
		{[]byte{0x16, 0x03}, false},
		{nil, false},
	} {
		if got := isTLSClientHello(c.b); got != c.want {
			t.Errorf("%x: %v", c.b, got)
		}
	}
}

func TestSniffReplaysBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsL, plainL := splitListener(ln, limits{peek: time.Second, total: 4})
	defer plainL.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := plainL.Accept()
	if err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "GET / HTTP/1.1\r\n" {
		t.Fatalf("bytes lost: %q", line)
	}
	c.Close()

	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	c, err = tlsL.Accept()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 0x16 || b[4] != 0x05 {
		t.Fatalf("tls bytes %x %v", b, err)
	}
	c.Close()
}

func TestSniffDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, plainL := splitListener(ln, limits{peek: 100 * time.Millisecond, total: 2})
	defer plainL.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("silent connection not closed: %v after %v", err, time.Since(start))
	}
}

func TestSniffPendingCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, plainL := splitListener(ln, limits{peek: 5 * time.Second, total: 2})
	defer plainL.Close()
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	extra, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := extra.Read(make([]byte, 1)); err == nil || time.Since(start) > time.Second {
		t.Fatalf("connection over the cap kept: %v", err)
	}
}

func TestSlotHeldUntilClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, plainL := splitListener(ln, limits{peek: time.Second, total: 10, perIP: 2})
	defer plainL.Close()
	var accepted []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\n"))
		s, err := plainL.Accept()
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, s)
	}
	// Both slots are still held after classification.
	extra, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("third connection from one address kept")
	}
	accepted[0].Close()
	time.Sleep(50 * time.Millisecond)
	again, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	_, _ = again.Write([]byte("GET / HTTP/1.1\r\n"))
	done := make(chan error, 1)
	go func() {
		c, err := plainL.Accept()
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released on close")
	}
}

type flakyListener struct {
	net.Listener
	fails int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.fails > 0 {
		f.fails--
		return nil, errors.New("too many open files")
	}
	return f.Listener.Accept()
}

func TestAcceptRetriesNonClosedErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, plainL := splitListener(&flakyListener{Listener: ln, fails: 3}, limits{})
	defer plainL.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\n"))
	done := make(chan error, 1)
	go func() {
		s, err := plainL.Accept()
		if err == nil {
			s.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop stopped on a transient error")
	}
}

func TestHTTPServerLimits(t *testing.T) {
	s := newHTTPServer(http.NotFoundHandler(), nil)
	if s.ReadHeaderTimeout <= 0 || s.ReadHeaderTimeout > 10*time.Second || s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 64<<10 ||
		s.IdleTimeout <= 0 || s.IdleTimeout > 2*time.Minute || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 {
		t.Fatalf("limits %+v", s)
	}
	if DefaultPeekTimeout > 5*time.Second {
		t.Fatalf("peek timeout %v", DefaultPeekTimeout)
	}
}

// TestLANFloodCannotBlockLoopbackConnection dials from 127.0.0.2 as the
// "LAN" flooder and from 127.0.0.1 as the owner.
func TestLANFloodCannotBlockLoopbackConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := limits{peek: 5 * time.Second, total: 6, perIP: 100, reserved: 2,
		local: func(a net.Addr) bool { return strings.HasPrefix(a.String(), "127.0.0.1:") }}
	_, plainL := splitListener(ln, lim)
	defer plainL.Close()
	flood := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 10; i++ {
		c, err := flood.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Skip("cannot bind 127.0.0.2:", err)
		}
		held = append(held, c)
	}
	time.Sleep(100 * time.Millisecond)
	owner, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	_, _ = owner.Write([]byte("GET / HTTP/1.1\r\n"))
	done := make(chan error, 1)
	go func() {
		for {
			c, err := plainL.Accept()
			if err != nil {
				done <- err
				return
			}
			if strings.HasPrefix(c.RemoteAddr().String(), "127.0.0.1:") {
				c.Close()
				done <- nil
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owner connection starved by LAN flood")
	}
}
