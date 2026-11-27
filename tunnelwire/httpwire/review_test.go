package httpwire

import (
	"net/http"
	"testing"
)

func TestUnderscoreSeaWiseHeaders(t *testing.T) {
	h := http.Header{"SeaWise_Visitor_Token": {"a"}, "seawise_stale-ok": {"b"}, "X-Keep": {"c"}}
	StripSeaWise(h)
	if len(h) != 1 || h.Get("X-Keep") != "c" {
		t.Fatal(h)
	}
	s, err := CheckExchange([]byte("GET / HTTP/1.1\r\n" + host + "SeaWise_Visitor_Token: a\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Header) != 1 {
		t.Fatal("underscore form kept", s.Header)
	}
}

func TestTrailerFramingFieldsRefused(t *testing.T) {
	for _, f := range []string{"Content-Length: 5", "Transfer-Encoding: chunked", "Host: other.example", "Trailer: X", "Authorization: Bearer x", "Content-Type: text/plain", "Connection: close", "TE: trailers", "Upgrade: h2c", "Cookie: a=b"} {
		in := "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n0\r\n" + f + "\r\n\r\n"
		if _, err := CheckExchange([]byte(in)); CodeOf(err) != CodeBadTrailer {
			t.Errorf("%s: %v", f, err)
		}
	}
	in := "POST / HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n0\r\nX-Checksum: 1\r\n\r\n"
	if _, err := CheckExchange([]byte(in)); err != nil {
		t.Fatal(err)
	}
}
