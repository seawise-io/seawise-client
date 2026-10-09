package adminui

import (
	"bufio"
	"io"
	"net"
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
	tlsL, plainL := splitListener(ln, time.Second, 4)
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
	_, plainL := splitListener(ln, 100*time.Millisecond, 2)
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
	_, plainL := splitListener(ln, 5*time.Second, 2)
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
