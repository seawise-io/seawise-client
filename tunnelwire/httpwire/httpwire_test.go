package httpwire

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLongHeaderLine(t *testing.T) {
	cookie := strings.Repeat("c", 20000)
	in := "GET / HTTP/1.1\r\n" + host + "Cookie: " + cookie + "\r\n\r\n"
	s, err := CheckExchange([]byte(in))
	if err != nil || s.Header["Cookie"][0] != cookie {
		t.Fatal(err)
	}
	at := "GET / HTTP/1.1\r\n" + host + "A: "
	in = at + strings.Repeat("a", MaxHeaderBytes-len(at)-4) + "\r\n\r\n"
	if len(in) != MaxHeaderBytes {
		t.Fatal(len(in))
	}
	if _, err := CheckExchange([]byte(in)); err != nil {
		t.Fatal("header block at the cap refused", err)
	}
	in = at + strings.Repeat("a", MaxHeaderBytes-len(at)-3) + "\r\n\r\n"
	if _, err := CheckExchange([]byte(in)); CodeOf(err) != CodeTooLarge {
		t.Fatal(err)
	}
}

func TestTrailerTooLarge(t *testing.T) {
	in := "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n0\r\nA: " + strings.Repeat("a", MaxHeaderBytes) + "\r\n\r\n"
	if _, err := CheckExchange([]byte(in)); CodeOf(err) != CodeTooLarge {
		t.Fatal(err)
	}
	in = "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n0\r\n: x\r\n\r\n"
	if _, err := CheckExchange([]byte(in)); CodeOf(err) != CodeMalformed {
		t.Fatal(err)
	}
	in = "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n0\r\nA: b\r\n"
	if _, err := CheckExchange([]byte(in)); CodeOf(err) != CodeTruncated {
		t.Fatal(err)
	}
}

func TestBodyReadsFromStream(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		b.Write([]byte("POST / HTTP/1.1\r\n" + host + "Content-Length: 6\r\n\r\nab"))
		time.Sleep(10 * time.Millisecond)
		b.Write([]byte("cdef"))
		time.Sleep(10 * time.Millisecond)
		b.Write([]byte("X"))
	}()
	br := bufio.NewReader(a)
	req, err := ReadRequest(br)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || string(body) != "abcdef" {
		t.Fatal(string(body), err)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Ended(br); err != nil {
		t.Fatal("bytes reported before they arrived")
	}
	if err := Trailing(br); CodeOf(err) != CodeTrailing {
		t.Fatal(err)
	}
}

func TestFixedBodySmallReads(t *testing.T) {
	f := &fixedBody{r: strings.NewReader("abcdefXYZ"), left: 6}
	p := make([]byte, 4)
	n, err := f.Read(p)
	if n != 4 || err != nil {
		t.Fatal(n, err)
	}
	n, err = f.Read(p)
	if n != 2 || err != nil || string(p[:2]) != "ef" {
		t.Fatal(n, err)
	}
	if n, err := f.Read(p); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
	f = &fixedBody{r: strings.NewReader("abc"), left: 3}
	if b, err := io.ReadAll(f); err != nil || string(b) != "abc" {
		t.Fatal(err)
	}
	f = &fixedBody{r: iotestEOF{}, left: 2}
	if n, err := f.Read(make([]byte, 2)); n != 2 || err != nil {
		t.Fatal("data with EOF at the exact end", n, err)
	}
}

type iotestEOF struct{}

func (iotestEOF) Read(p []byte) (int, error) { return copy(p, "zz"), io.EOF }

type errAfter struct{ err error }

func (e errAfter) Read([]byte) (int, error) { return 0, e.err }

type zeroThenEOF struct{ n int }

func (z *zeroThenEOF) Read([]byte) (int, error) {
	if z.n < 3 {
		z.n++
		return 0, nil
	}
	return 0, io.EOF
}

func TestTrailing(t *testing.T) {
	if err := Trailing(strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if err := Trailing(&zeroThenEOF{}); err != nil {
		t.Fatal(err)
	}
	if err := Trailing(errAfter{io.ErrClosedPipe}); err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	br := bufio.NewReader(strings.NewReader("x"))
	br.Peek(1)
	if err := Ended(br); CodeOf(err) != CodeTrailing {
		t.Fatal(err)
	}
}

func TestChunkedBodyErrors(t *testing.T) {
	in := "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(in))
	req, err := ReadRequest(br)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(req.Body)
	if err != nil || string(b) != "hello" || req.Trailer != nil {
		t.Fatal(err, req.Trailer)
	}
	if n, err := req.Body.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("read after EOF")
	}
	if req.Body.Close() != nil {
		t.Fatal()
	}
	req.Trailer = http.Header{"X-Pre": {"1"}}
	in2 := "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\nTrailer: X-Sum\r\n\r\n0\r\nX-Sum: 3\r\n\r\n"
	req2, err := ReadRequest(bufio.NewReader(strings.NewReader(in2)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(req2.Body); err != nil || req2.Trailer.Get("X-Sum") != "3" {
		t.Fatal(err, req2.Trailer)
	}
}

func TestStripSeaWise(t *testing.T) {
	h := http.Header{"Seawise-Visitor-Token": {"a"}, "seawise-stale-ok": {"b"}, "X-Keep": {"c"}, "Seawise-Visitor-Tokens": {"d"}}
	StripSeaWise(h)
	if len(h) != 2 || h.Get("X-Keep") != "c" || h.Get("Seawise-Visitor-Tokens") != "d" {
		t.Fatal(h)
	}
}

func TestTchar(t *testing.T) {
	for _, c := range []byte("!#$%&'*+-.^_`|~09azAZ") {
		if !isTchar(c) {
			t.Errorf("%q", c)
		}
	}
	for _, c := range []byte("\"(),/:;<=>?@[\\]{} \t\x00\x7f/@[`{") {
		if c != '`' && isTchar(c) {
			t.Errorf("%q", c)
		}
	}
}

func TestErrorText(t *testing.T) {
	if fail(CodeTrailing).Error() != "tunnelwire http: trailing_bytes" || CodeOf(io.EOF) != "" {
		t.Fatal()
	}
	_ = bytes.MinRead
}
