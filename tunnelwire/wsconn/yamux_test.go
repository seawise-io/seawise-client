package wsconn

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
)

// pipeWS frames binary messages with a length prefix over a net.Conn.
type pipeWS struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
}

func (p *pipeWS) NextReader() (bool, io.Reader, error) {
	var n [4]byte
	if _, err := io.ReadFull(p.br, n[:]); err != nil {
		return false, nil, err
	}
	return true, io.LimitReader(p.br, int64(binary.BigEndian.Uint32(n[:]))), nil
}

func (p *pipeWS) WriteBinary(b []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_, err := p.c.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b)))) //nolint:gosec // test frames are small
	if err != nil {
		return err
	}
	_, err = p.c.Write(b)
	return err
}

func (p *pipeWS) Close() error { return p.c.Close() }

func carried(c net.Conn) net.Conn {
	return NetConn{Conn: New(&pipeWS{c: c, br: bufio.NewReader(c)}), Under: c}
}

// go-yamux sets a write deadline before its writes; a session over NetConn
// must survive that and stay usable after its 10 s write timeout passed idle.
func TestYamuxOverNetConnSurvivesIdle(t *testing.T) {
	if testing.Short() || os.Getenv("SEAWISE_SKIP_SLOW_TESTS") != "" {
		t.Skip("waits 11 s")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvc := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			srvc <- c
		}
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-srvc
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.LogOutput = io.Discard
	cli, err := yamux.Client(carried(cc), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv, err := yamux.Server(carried(sc), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			st, err := srv.AcceptStream()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(st, st); _ = st.Close() }()
		}
	}()
	echo := func(msg string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := cli.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		_ = st.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := st.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(st, got); err != nil || string(got) != msg {
			t.Fatal(string(got), err)
		}
	}
	echo("before")
	time.Sleep(11 * time.Second)
	if cli.IsClosed() || srv.IsClosed() {
		t.Fatal("session closed while idle")
	}
	echo("after idle")
}
