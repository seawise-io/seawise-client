package httpwire

import (
	"strings"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

type vcase struct {
	Name    string         `json:"name"`
	Kind    string         `json:"kind"`
	Input   string         `json:"input,omitempty"`
	Context map[string]any `json:"context,omitempty"`
	Expect  string         `json:"expect"`
	Result  any            `json:"result,omitempty"`
}

type vfile struct {
	Format string  `json:"format"`
	Note   string  `json:"note"`
	Cases  []vcase `json:"cases"`
}

const host = "Host: app.example.test\r\n"

func genRequestBytes() vfile {
	var cs []vcase
	req := func(name, in, expect string) {
		c := vcase{Name: name, Kind: "request", Input: in, Expect: expect}
		if expect == "ok" {
			s, err := CheckExchange([]byte(in))
			if err != nil {
				panic(name + ": " + err.Error())
			}
			c.Result = s
		}
		cs = append(cs, c)
	}
	get := "GET /a?b=1 HTTP/1.1\r\n" + host + "Accept: */*\r\n\r\n"
	post := "POST /submit HTTP/1.1\r\n" + host + "Content-Length: 5\r\n\r\nhello"
	chunked := "POST /up HTTP/1.1\r\n" + host + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Sum: 1\r\n\r\n"
	req("valid-get", get, "ok")
	req("valid-post-content-length", post, "ok")
	req("valid-chunked-with-trailer", chunked, "ok")
	req("two-requests-on-one-stream", get+get, "trailing_bytes")
	req("pipelined-after-body", post+get, "trailing_bytes")
	req("pipelined-after-chunked", chunked+get, "trailing_bytes")
	req("bytes-after-request", get+"x", "trailing_bytes")
	req("bytes-after-upgrade-request-before-101", "GET /ws HTTP/1.1\r\n"+host+"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x05hello", "trailing_bytes")
	req("content-length-with-transfer-encoding", "POST / HTTP/1.1\r\n"+host+"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "cl_and_te")
	req("transfer-encoding-with-content-length", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", "cl_and_te")
	req("content-length-twice", "POST / HTTP/1.1\r\n"+host+"Content-Length: 1\r\nContent-Length: 1\r\n\r\na", "malformed")
	req("transfer-encoding-twice", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "malformed")
	req("transfer-encoding-gzip-chunked", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", "malformed")
	req("transfer-encoding-identity", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: identity\r\n\r\n", "malformed")
	req("content-length-negative", "POST / HTTP/1.1\r\n"+host+"Content-Length: -1\r\n\r\n", "malformed")
	req("content-length-plus", "POST / HTTP/1.1\r\n"+host+"Content-Length: +5\r\n\r\nhello", "malformed")
	req("seawise-visitor-token-stripped", "GET / HTTP/1.1\r\n"+host+"SeaWise-Visitor-Token: eyJh.eyJi.c2ln\r\n\r\n", "ok")
	req("seawise-stale-ok-stripped", "GET / HTTP/1.1\r\n"+host+"SeaWise-Stale-Ok: eyJh.eyJi.c2ln\r\n\r\n", "ok")
	req("seawise-headers-any-case-stripped", "GET / HTTP/1.1\r\n"+host+"seawise-visitor-token: a\r\nSEAWISE-STALE-OK: b\r\n\r\n", "ok")
	req("seawise-header-in-trailer-stripped", "POST /up HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\n\r\n0\r\nSeaWise-Visitor-Token: a\r\nX-Sum: 2\r\n\r\n", "ok")
	req("bare-lf-line", "GET / HTTP/1.1\n"+host+"\r\n", "malformed")
	req("bare-lf-header", "GET / HTTP/1.1\r\n"+host+"A: b\n\r\n", "malformed")
	req("bare-cr-in-value", "GET / HTTP/1.1\r\n"+host+"A: b\rc\r\n\r\n", "malformed")
	req("nul-in-value", "GET / HTTP/1.1\r\n"+host+"A: b\x00c\r\n\r\n", "malformed")
	req("tab-in-value", "GET / HTTP/1.1\r\n"+host+"A: b\tc\r\n\r\n", "ok")
	req("del-in-value", "GET / HTTP/1.1\r\n"+host+"A: b\x7fc\r\n\r\n", "malformed")
	req("obs-fold", "GET / HTTP/1.1\r\n"+host+"A: b\r\n c\r\n\r\n", "malformed")
	req("space-before-colon", "GET / HTTP/1.1\r\n"+host+"Content-Length : 5\r\n\r\nhello", "malformed")
	req("empty-header-name", "GET / HTTP/1.1\r\n"+host+": v\r\n\r\n", "malformed")
	req("no-colon", "GET / HTTP/1.1\r\n"+host+"novalue\r\n\r\n", "malformed")
	req("empty-request-line", "\r\n"+get, "malformed")
	req("http-1.0", "GET / HTTP/1.0\r\n"+host+"\r\n", "version")
	req("http-2-preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "version")
	req("absolute-form-target", "GET http://other.example/ HTTP/1.1\r\n"+host+"\r\n", "malformed")
	req("authority-form-connect", "CONNECT other.example:443 HTTP/1.1\r\n"+host+"\r\n", "malformed")
	req("options-asterisk", "OPTIONS * HTTP/1.1\r\n"+host+"\r\n", "ok")
	req("get-asterisk", "GET * HTTP/1.1\r\n"+host+"\r\n", "malformed")
	req("missing-host", "GET / HTTP/1.1\r\n\r\n", "malformed")
	req("two-hosts", "GET / HTTP/1.1\r\n"+host+host+"\r\n", "malformed")
	req("truncated-headers", "GET / HTTP/1.1\r\n"+host, "truncated")
	req("truncated-body", "POST / HTTP/1.1\r\n"+host+"Content-Length: 10\r\n\r\nhello", "truncated")
	req("truncated-chunked", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\n\r\n5\r\nhel", "malformed")
	req("chunk-size-bare-lf", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n", "malformed")
	req("chunk-size-invalid", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n", "malformed")
	req("chunk-trailer-bare-lf", "POST / HTTP/1.1\r\n"+host+"Transfer-Encoding: chunked\r\n\r\n0\r\nA: b\n\r\n", "malformed")
	req("header-block-too-large", "GET / HTTP/1.1\r\n"+host+"A: "+strings.Repeat("a", MaxHeaderBytes)+"\r\n\r\n", "too_large")

	h2 := func(name, field, value, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "h2_field", Context: map[string]any{"name": field, "value": value}, Expect: expect})
	}
	h2("h2-ok", "accept", "text/html", "ok")
	h2("h2-ok-pseudo-path", ":path", "/a?b", "ok")
	h2("h2-ok-te-trailers", "te", "trailers", "ok")
	h2("h2-ok-empty-value", "x-empty", "", "ok")
	h2("h2-value-cr", "x-a", "b\rc", "bad_field")
	h2("h2-value-lf", "x-a", "b\nX-Injected: 1", "bad_field")
	h2("h2-value-nul", "x-a", "b\x00c", "bad_field")
	h2("h2-value-crlf-smuggle", "x-a", "b\r\n\r\nGET /admin HTTP/1.1", "bad_field")
	h2("h2-value-leading-space", "x-a", " b", "bad_field")
	h2("h2-value-trailing-tab", "x-a", "b\t", "bad_field")
	h2("h2-name-uppercase", "X-A", "b", "bad_field")
	h2("h2-name-cr", "x-a\r", "b", "bad_field")
	h2("h2-name-lf", "x-a\nx-b", "b", "bad_field")
	h2("h2-name-nul", "x\x00a", "b", "bad_field")
	h2("h2-name-colon-inside", "x:a", "b", "bad_field")
	h2("h2-name-space", "x a", "b", "bad_field")
	h2("h2-name-empty", "", "b", "bad_field")
	h2("h2-unknown-pseudo", ":foo", "b", "bad_field")
	h2("h2-transfer-encoding", "transfer-encoding", "chunked", "bad_field")
	h2("h2-connection", "connection", "close", "bad_field")
	h2("h2-keep-alive", "keep-alive", "timeout=5", "bad_field")
	h2("h2-upgrade", "upgrade", "websocket", "bad_field")
	h2("h2-te-gzip", "te", "gzip", "bad_field")

	up := func(name, headers string, status int, expect string) {
		cs = append(cs, vcase{Name: name, Kind: "upgrade", Input: "GET /ws HTTP/1.1\r\n" + host + headers + "\r\n", Context: map[string]any{"status": status}, Expect: expect})
	}
	ws := "Connection: Upgrade\r\nUpgrade: websocket\r\n"
	up("upgrade-101", ws, 101, "ok")
	up("upgrade-connection-list", "Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n", 101, "ok")
	up("upgrade-answered-200", ws, 200, "not_upgraded")
	up("upgrade-answered-400", ws, 400, "not_upgraded")
	up("101-without-upgrade-request", "", 101, "not_upgraded")
	up("upgrade-header-without-connection", "Upgrade: websocket\r\n", 101, "not_upgraded")
	return vfile{Format: "request_bytes", Note: vkeys.Note, Cases: cs}
}
