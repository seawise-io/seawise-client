// Package httpwire enforces the request-bytes rules of a seawise-tunnel/1
// data stream: exactly one HTTP/1.1 request per stream, strict header
// syntax, no Content-Length together with Transfer-Encoding, raw bytes only
// after a 101, SeaWise headers stripped, and the h2 field checks the edge
// applies before translating to HTTP/1.1.
package httpwire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

// MaxHeaderBytes caps the request line and header block, and separately the
// trailer block.
const MaxHeaderBytes = 64 << 10

// SeaWiseHeaders never reach a target: the stream header carries them.
var SeaWiseHeaders = []string{"SeaWise-Visitor-Token", "SeaWise-Stale-Ok"}

// Code classifies a request-bytes error.
type Code string

const (
	CodeMalformed   Code = "malformed"
	CodeTooLarge    Code = "too_large"
	CodeCLAndTE     Code = "cl_and_te"
	CodeBadField    Code = "bad_field"
	CodeTrailing    Code = "trailing_bytes"
	CodeVersion     Code = "version"
	CodeTruncated   Code = "truncated"
	CodeNotUpgraded Code = "not_upgraded"
	CodeBadTrailer  Code = "bad_trailer"
)

// Error is a request-bytes error.
type Error struct{ Code Code }

func (e *Error) Error() string { return "tunnelwire http: " + string(e.Code) }

func fail(c Code) error { return &Error{Code: c} }

// CodeOf returns the code of an httpwire error, or "".
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func isTchar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// connectionSpecific are h2 fields that have no meaning in h2 and would
// change framing once translated to HTTP/1.1 (RFC 9113 section 8.2.2).
var connectionSpecific = []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"}

var pseudo = []string{":method", ":scheme", ":authority", ":path", ":protocol"}

// CheckH2Field checks one h2 field before translation to HTTP/1.1:
// RFC 9113 section 8.2.1 syntax (no uppercase, no colon outside the
// pseudo-header names, no CR, LF or NUL anywhere, no leading or trailing
// whitespace in the value) and no connection-specific fields.
func CheckH2Field(name, value string) error {
	if name == "" {
		return fail(CodeBadField)
	}
	if name[0] == ':' {
		ok := false
		for _, p := range pseudo {
			ok = ok || name == p
		}
		if !ok {
			return fail(CodeBadField)
		}
	} else {
		for i := 0; i < len(name); i++ {
			c := name[i]
			if !isTchar(c) || c >= 'A' && c <= 'Z' {
				return fail(CodeBadField)
			}
		}
		for _, n := range connectionSpecific {
			if name == n {
				return fail(CodeBadField)
			}
		}
		if name == "te" && value != "trailers" {
			return fail(CodeBadField)
		}
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c == 0 || c == '\r' || c == '\n' {
			return fail(CodeBadField)
		}
	}
	if value != "" && (value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
		return fail(CodeBadField)
	}
	return nil
}

func isSeaWise(name string) bool {
	name = strings.ReplaceAll(name, "_", "-")
	for _, s := range SeaWiseHeaders {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}

// StripSeaWise removes the SeaWise headers from h, in any letter case.
func StripSeaWise(h http.Header) {
	for k := range h {
		if isSeaWise(k) {
			delete(h, k)
		}
	}
}

// readBlock reads CRLF-terminated lines up to and including the empty line
// and checks each one: no bare CR or LF, no NUL or other control byte
// except HTAB, no obs-fold, and "name: value" with a token name on every
// line after the first when firstIsStart is set (every line otherwise).
func readBlock(br *bufio.Reader, firstIsStart bool) ([]byte, []string, error) {
	var raw []byte
	var names []string
	for first := true; ; first = false {
		start := len(raw)
		for {
			part, err := br.ReadSlice('\n')
			if len(raw)+len(part) > MaxHeaderBytes {
				return nil, nil, fail(CodeTooLarge)
			}
			raw = append(raw, part...)
			if err == nil {
				break
			}
			if err != bufio.ErrBufferFull {
				return nil, nil, fail(CodeTruncated)
			}
		}
		line := raw[start:]
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, nil, fail(CodeMalformed)
		}
		body := line[:len(line)-2]
		for _, c := range body {
			if c < 0x20 && c != '\t' || c == 0x7f {
				return nil, nil, fail(CodeMalformed)
			}
		}
		if len(body) == 0 {
			if first && firstIsStart {
				return nil, nil, fail(CodeMalformed)
			}
			return raw, names, nil
		}
		if first && firstIsStart {
			continue
		}
		colon := bytes.IndexByte(body, ':')
		if colon <= 0 {
			return nil, nil, fail(CodeMalformed)
		}
		for _, c := range body[:colon] {
			if !isTchar(c) {
				return nil, nil, fail(CodeMalformed)
			}
		}
		names = append(names, strings.ToLower(string(body[:colon])))
	}
}

// originForm reports whether the request target is "/..." or, for OPTIONS,
// "*". Absolute and authority forms could name a host other than Host.
func originForm(req *http.Request) bool {
	return strings.HasPrefix(req.RequestURI, "/") || req.Method == http.MethodOptions && req.RequestURI == "*"
}

// ReadRequest reads exactly one HTTP/1.1 request from br. The body reads
// straight from br, so after it returns io.EOF, br holds only bytes that
// follow the request; use Ended or Trailing to refuse them. SeaWise headers
// are stripped from the header and, once the body is read, the trailer.
func ReadRequest(br *bufio.Reader) (*http.Request, error) {
	raw, names, err := readBlock(br, true)
	if err != nil {
		return nil, err
	}
	cl, te := 0, 0
	for _, n := range names {
		switch n {
		case "content-length":
			cl++
		case "transfer-encoding":
			te++
		}
	}
	if cl > 0 && te > 0 {
		return nil, fail(CodeCLAndTE)
	}
	if cl > 1 || te > 1 {
		return nil, fail(CodeMalformed)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fail(CodeMalformed)
	}
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		return nil, fail(CodeVersion)
	}
	if req.Host == "" || !originForm(req) {
		return nil, fail(CodeMalformed)
	}
	StripSeaWise(req.Header)
	switch {
	case len(req.TransferEncoding) > 0:
		req.Body = &chunkedBody{br: br, cr: httputil.NewChunkedReader(br), req: req}
	case req.ContentLength > 0:
		req.Body = &fixedBody{r: br, left: req.ContentLength}
	default:
		req.Body = http.NoBody
	}
	return req, nil
}

type fixedBody struct {
	r    io.Reader
	left int64
}

func (b *fixedBody) Read(p []byte) (int, error) {
	if b.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	if err == io.EOF {
		if b.left > 0 {
			return n, fail(CodeTruncated)
		}
		err = nil
	}
	return n, err
}

func (b *fixedBody) Close() error { return nil }

type chunkedBody struct {
	br   *bufio.Reader
	cr   io.Reader
	req  *http.Request
	done bool
}

func (b *chunkedBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	n, err := b.cr.Read(p)
	if err == io.EOF {
		if terr := b.readTrailer(); terr != nil {
			return n, terr
		}
		b.done = true
		return n, io.EOF
	}
	if err != nil {
		return n, fail(CodeMalformed)
	}
	return n, nil
}

// trailerForbidden are fields a trailer may not carry: framing, routing,
// connection control, authentication and content metadata
// (RFC 9110 section 6.5.1).
var trailerForbidden = []string{
	"content-length", "transfer-encoding", "host", "trailer", "te", "connection", "upgrade",
	"keep-alive", "proxy-connection", "authorization", "proxy-authorization", "cookie",
	"content-type", "content-encoding", "content-range", "range", "expect", "max-forwards",
	"cache-control",
}

func (b *chunkedBody) readTrailer() error {
	raw, names, err := readBlock(b.br, false)
	if err != nil {
		return err
	}
	for _, n := range names {
		n = strings.ReplaceAll(n, "_", "-")
		for _, f := range trailerForbidden {
			if n == f {
				return fail(CodeBadTrailer)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	tr, err := http.ReadRequest(bufio.NewReader(io.MultiReader(strings.NewReader("GET / HTTP/1.1\r\nHost: x\r\n"), bytes.NewReader(raw))))
	if err != nil {
		return fail(CodeMalformed)
	}
	delete(tr.Header, "Host")
	StripSeaWise(tr.Header)
	if b.req.Trailer == nil {
		b.req.Trailer = http.Header{}
	}
	for k, v := range tr.Header {
		b.req.Trailer[k] = v
	}
	return nil
}

func (b *chunkedBody) Close() error { return nil }

// Ended returns CodeTrailing if br already holds bytes after the request.
// Call it after the body returned io.EOF.
func Ended(br *bufio.Reader) error {
	if br.Buffered() > 0 {
		return fail(CodeTrailing)
	}
	return nil
}

// Trailing blocks until r has another byte or ends. It returns nil at
// io.EOF and CodeTrailing when a byte arrives; run it while the response
// is outstanding and reset the stream on CodeTrailing. It must not run
// once a 101 was forwarded: the bytes then belong to the upgrade.
func Trailing(r io.Reader) error {
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			return fail(CodeTrailing)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func hasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// AsksUpgrade reports whether req asks for a protocol upgrade.
func AsksUpgrade(req *http.Request) bool {
	return req.Header.Get("Upgrade") != "" && hasToken(req.Header, "Connection", "upgrade")
}

// RawAfter reports whether the stream may carry raw bytes after a response
// with status to req: only a 101 to a request that asked for an upgrade.
// Any other response ends the stream after its body.
func RawAfter(req *http.Request, status int) error {
	if status == http.StatusSwitchingProtocols && AsksUpgrade(req) {
		return nil
	}
	return fail(CodeNotUpgraded)
}

// Summary describes a request read by CheckExchange.
type Summary struct {
	Method   string              `json:"method"`
	Target   string              `json:"target"`
	Header   map[string][]string `json:"header"`
	Trailer  map[string][]string `json:"trailer,omitempty"`
	BodyLen  int                 `json:"body_len"`
	Upgrades bool                `json:"upgrade"`
}

// CheckExchange reads one request from a complete byte buffer, its whole
// body, and refuses any byte after it.
func CheckExchange(b []byte) (*Summary, error) {
	br := bufio.NewReader(bytes.NewReader(b))
	req, err := ReadRequest(br)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	if err := Ended(br); err != nil {
		return nil, err
	}
	if err := Trailing(br); err != nil {
		return nil, err
	}
	s := &Summary{Method: req.Method, Target: req.RequestURI, Header: map[string][]string{}, BodyLen: len(body), Upgrades: AsksUpgrade(req)}
	for k, v := range req.Header {
		s.Header[k] = v
	}
	if req.Host != "" {
		s.Header["Host"] = []string{req.Host}
	}
	if len(req.Trailer) > 0 {
		s.Trailer = req.Trailer
	}
	return s, nil
}
