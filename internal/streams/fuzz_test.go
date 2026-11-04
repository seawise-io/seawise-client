package streams

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/forwarder"
	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/session"
	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/visitor"
)

// memStream is a stream over fixed input bytes.
type memStream struct {
	in  *bytes.Reader
	mu  sync.Mutex
	out bytes.Buffer
}

func (m *memStream) Read(p []byte) (int, error) { return m.in.Read(p) }
func (m *memStream) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.out.Write(p)
}
func (m *memStream) CloseWrite() error                { return nil }
func (m *memStream) Close() error                     { return nil }
func (m *memStream) Reset() error                     { return nil }
func (m *memStream) SetReadDeadline(time.Time) error  { return nil }
func (m *memStream) SetWriteDeadline(time.Time) error { return nil }

func (m *memStream) written() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.out.Bytes()...)
}

// memUp is an app that answers resp and records what it was sent.
type memUp struct {
	resp *bytes.Reader
	mu   sync.Mutex
	got  bytes.Buffer
}

func (u *memUp) Read(p []byte) (int, error) { return u.resp.Read(p) }
func (u *memUp) Write(p []byte) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.got.Write(p)
}
func (u *memUp) Close() error      { return nil }
func (u *memUp) CloseWrite() error { return nil }

func fuzzServer(t testing.TB) *Server {
	ks := testKeySet(t)
	g, err := visitor.New(visitor.Config{KeySet: func() *protocol.KeySet { return ks }, Mode: func() visitor.Mode { return visitor.Enforce },
		Now: func() time.Time { return time.Unix(exp0-60, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Gate: g, HeadTimeout: time.Second, IdleTimeout: time.Minute, CloseWait: time.Second,
		Targets: func() []store.Target {
			return []store.Target{{LocalID: "loc-a", ServerServiceID: appA, Host: "127.0.0.1", Port: 1, ServerPublic: true}}
		},
		Dial: func(context.Context, string) (*forwarder.Upstream, error) { return nil, forwarder.ErrNoApp }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func FuzzStreamHeader(f *testing.F) {
	for _, tok := range []string{"", token(appA, exp0), token(appB, exp0)} {
		for _, app := range []string{appA, appB} {
			h := header(app, tok)
			b, _ := wire.AppendStreamHeader(nil, h, nil)
			f.Add(append(b, get("/")...))
		}
	}
	f.Add([]byte{0, 0})
	f.Add([]byte{0xff, 0xff, 1})
	s := fuzzServer(f)
	rs := routeSet(map[string]bool{appA: true, appB: false})
	ds := session.DataSession{Routes: func() *claims.RouteSet { return rs }}
	f.Fuzz(func(t *testing.T, in []byte) {
		st := &memStream{in: bytes.NewReader(in)}
		s.handle(context.Background(), st, ds, newRegistry())
		out := st.written()
		if len(out) == 0 {
			return
		}
		code, err := wire.ReadStreamReply(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("bad reply %x: %v", out, err)
		}
		if n := 2 + (int(out[0])<<8 | int(out[1])); n != len(out) {
			t.Fatalf("bytes after the reply: %x", out)
		}
		if code == pb.ReplyCode_ACCEPTED {
			t.Fatal("accepted without a target")
		}
	})
}

func FuzzExchange(f *testing.F) {
	for _, r := range []string{get("/"), upgradeReq, get("/", "SeaWise-Visitor-Token: x\r\n"),
		"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nSeaWise-Stale-Ok: y\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi", get("/") + "trailing"} {
		f.Add([]byte(r), []byte(okResponse))
	}
	f.Add([]byte(upgradeReq+"x"), []byte("HTTP/1.1 101 Switching Protocols\r\n\r\nraw"))
	f.Add([]byte(get("/")), []byte("HTTP/1.1 103 Early\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"))
	s := fuzzServer(f)
	f.Fuzz(func(t *testing.T, req, resp []byte) {
		st := &memStream{in: bytes.NewReader(req)}
		up := &memUp{resp: bytes.NewReader(resp)}
		x := newExchange(s, st, up)
		_ = x.run()
		up.mu.Lock()
		sent := up.got.String()
		up.mu.Unlock()
		low := strings.ToLower(strings.ReplaceAll(sent, "_", "-"))
		if i := strings.Index(low, "\r\n\r\n"); i >= 0 {
			low = low[:i]
		}
		if strings.Contains(low, "\nseawise-visitor-token") || strings.Contains(low, "\nseawise-stale-ok") {
			t.Fatalf("SeaWise header reached the app: %q", sent)
		}
		if x.in.Load() != int64(len(sent)) || x.out.Load() != int64(len(st.written())) {
			t.Fatal("byte counts")
		}
		if sent != "" {
			if _, err := httpReadable(sent); err != nil {
				t.Fatalf("app got an unreadable request %q: %v", sent, err)
			}
		}
	})
}

func FuzzResponseHead(f *testing.F) {
	f.Add([]byte(okResponse))
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n"))
	f.Add([]byte("HTTP/1.0 200\n\n"))
	f.Add([]byte("HTTP/1.1 99 X\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		head, status, err := readHead(bufio.NewReaderSize(bytes.NewReader(b), 16))
		if err != nil {
			return
		}
		if !bytes.HasPrefix(b, head) || len(head) > MaxResponseHead || status < 100 || status > 999 {
			t.Fatalf("%q %d", head, status)
		}
		if !bytes.HasSuffix(head, []byte("\n\n")) && !bytes.HasSuffix(head, []byte("\n\r\n")) {
			t.Fatalf("head not ended: %q", head)
		}
	})
}

func httpReadable(s string) (string, error) {
	br := bufio.NewReader(strings.NewReader(s))
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(line, " HTTP/1.1\r\n") {
		return "", errors.New("request line")
	}
	_, err = io.Copy(io.Discard, br)
	return line, err
}
