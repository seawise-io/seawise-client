package visitor

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Strict JSON as the platform reads token headers and claims: valid UTF-8,
// one object at the top, no duplicate member at any depth, no null, finite
// numbers read as JavaScript doubles, at most maxDepth nested containers.
// Values are map[string]any, []any, string, float64 and bool. An escaped
// lone surrogate keeps its WTF-8 bytes, as distinct as in JavaScript.

const maxDepth = 8

var errSyntax = fail(Malformed, "syntax error")

// sentinel ends the text: NUL is never valid outside a string and never raw
// inside one, so every step stops on it and no read needs a bounds check.
const sentinel = "\x00\x00\x00\x00\x00\x00\x00\x00"

type jsonParser struct {
	s     string
	i     int
	depth int
}

func parseJSON(b []byte) (map[string]any, error) {
	if !utf8.Valid(b) {
		return nil, fail(Malformed, "invalid UTF-8")
	}
	p := &jsonParser{s: string(b) + sentinel}
	p.space()
	if p.s[p.i] != '{' {
		return nil, fail(Malformed, "not an object")
	}
	v, err := p.object()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(b) {
		return nil, errSyntax
	}
	return v, nil
}

// parseObject parses an object with every required member and no member
// outside required and optional.
func parseObject(b []byte, required, optional []string) (map[string]any, error) {
	o, err := parseJSON(b)
	if err != nil {
		return nil, err
	}
	for _, k := range required {
		if _, ok := o[k]; !ok {
			return nil, fail(Malformed, "missing member")
		}
	}
	for k := range o {
		if !contains(required, k) && !contains(optional, k) {
			return nil, fail(Malformed, "unknown member")
		}
	}
	return o, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func (p *jsonParser) space() {
	for {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonParser) value() (any, error) {
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		return nil, fail(Malformed, "null value")
	}
	return nil, errSyntax
}

func (p *jsonParser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return fail(Malformed, "nested too deeply")
	}
	p.i++
	p.space()
	return nil
}

func (p *jsonParser) leave() {
	p.i++
	p.depth--
}

// next consumes a separator or the closing byte; done reports the close.
func (p *jsonParser) next(closing byte) (done bool, err error) {
	p.space()
	switch p.s[p.i] {
	case ',':
		p.i++
		p.space()
		return false, nil
	case closing:
		p.leave()
		return true, nil
	}
	return false, errSyntax
}

func (p *jsonParser) object() (map[string]any, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	o := map[string]any{}
	if p.s[p.i] == '}' {
		p.leave()
		return o, nil
	}
	for {
		if p.s[p.i] != '"' {
			return nil, errSyntax
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.s[p.i] != ':' {
			return nil, errSyntax
		}
		p.i++
		p.space()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, dup := o[k]; dup {
			return nil, fail(Malformed, "duplicate member")
		}
		o[k] = v
		if done, err := p.next('}'); err != nil || done {
			return o, err
		}
	}
}

func (p *jsonParser) array() ([]any, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	a := []any{}
	if p.s[p.i] == ']' {
		p.leave()
		return a, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		if done, err := p.next(']'); err != nil || done {
			return a, err
		}
	}
}

// hex4 reads four hex digits; the sentinel guarantees four bytes.
func hex4(s string) (rune, bool) {
	n, err := strconv.ParseUint(s[:4], 16, 16)
	return rune(n), err == nil
}

func isSurrogate(r, lo rune) bool { return r >= lo && r < lo+0x400 }

func (p *jsonParser) str() (string, error) {
	p.i++
	start := p.i
	var out []byte
	for {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			if out == nil {
				return p.s[start : p.i-1], nil
			}
			return string(out), nil
		case c < 0x20:
			return "", errSyntax
		case c != '\\':
			p.i++
			if out != nil {
				out = append(out, c)
			}
			continue
		}
		if out == nil {
			out = []byte(p.s[start:p.i])
		}
		e := p.s[p.i+1]
		p.i += 2
		if e != 'u' {
			r, ok := simpleEscape[e]
			if !ok {
				return "", errSyntax
			}
			out = append(out, r)
			continue
		}
		r, ok := hex4(p.s[p.i:])
		if !ok {
			return "", errSyntax
		}
		p.i += 4
		if isSurrogate(r, 0xd800) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
			if lo, ok := hex4(p.s[p.i+2:]); ok && isSurrogate(lo, 0xdc00) {
				r = 0x10000 + (r-0xd800)<<10 + (lo - 0xdc00)
				p.i += 6
			}
		}
		if isSurrogate(r, 0xd800) || isSurrogate(r, 0xdc00) {
			out = append(out, byte(0xe0|r>>12), byte(0x80|(r>>6)&0x3f), byte(0x80|r&0x3f)) //nolint:gosec // r is a surrogate
			continue
		}
		out = utf8.AppendRune(out, r)
	}
}

var simpleEscape = map[byte]byte{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}

func (p *jsonParser) digits() bool {
	start := p.i
	for p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	return p.i > start
}

func (p *jsonParser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.s[p.i] == '0' {
		p.i++
	} else if !p.digits() {
		return nil, errSyntax
	}
	if p.s[p.i] == '.' {
		p.i++
		if !p.digits() {
			return nil, errSyntax
		}
	}
	if p.s[p.i] == 'e' || p.s[p.i] == 'E' {
		p.i++
		if p.s[p.i] == '+' || p.s[p.i] == '-' {
			p.i++
		}
		if !p.digits() {
			return nil, errSyntax
		}
	}
	// Overflow gives ±Inf (refused); underflow gives 0, as JSON.parse does.
	f, _ := strconv.ParseFloat(p.s[start:p.i], 64)
	if math.IsInf(f, 0) {
		return nil, fail(Malformed, "number out of range")
	}
	return f, nil
}

// isCount reports a safe integer (Number.isSafeInteger) of at least min.
func isCount(v any, min float64) bool {
	f, ok := v.(float64)
	return ok && f == math.Trunc(f) && math.Abs(f) <= 1<<53-1 && f >= min
}
