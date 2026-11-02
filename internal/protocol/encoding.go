package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxTime   = 1<<53 - 1
	maxDepth  = 8
	leewaySec = 300
)

var b64 = base64.RawURLEncoding.Strict()

// b64Decode accepts only canonical unpadded base64url. The standard decoder
// skips CR and LF even in strict mode, so they are refused first.
func b64Decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("line break in base64url")
	}
	return b64.DecodeString(s)
}

func b64Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decodeObject decodes a JSON object into v with the strict rules of the
// protocol: valid UTF-8, no duplicate members at any depth, no null, every
// required member present, no member outside required and optional, nothing
// after the object. Member names match exactly; encoding/json alone would
// match them case-insensitively. Nested objects must be decoded as
// json.RawMessage and passed through decodeObject again.
func decodeObject(b []byte, v any, required []string, optional ...string) error {
	if !utf8.Valid(b) {
		return fail(CodeMalformed, "invalid UTF-8")
	}
	keys, err := scanObject(b)
	if err != nil {
		return fail(CodeMalformed, "%v", err)
	}
	for _, k := range required {
		if !keys[k] {
			return fail(CodeMalformed, "missing member %q", k)
		}
	}
	for k := range keys {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return fail(CodeMalformed, "unknown member")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(CodeMalformed, "json: %v", sanitizeJSONErr(err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail(CodeMalformed, "trailing data")
	}
	return nil
}

// sanitizeJSONErr keeps the error type and position, not the input.
func sanitizeJSONErr(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return "syntax error"
	case errors.As(err, &typ):
		return "wrong type for " + typ.Field
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		return "unknown member"
	}
	return "invalid"
}

// scanObject checks that b is a single JSON object with no duplicate member
// names and no null values, and returns its top-level member names.
func scanObject(b []byte) (map[string]bool, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.New("syntax error")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	keys := map[string]bool{}
	if err := scanMembers(dec, keys, 1); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return keys, nil
}

func scanMembers(dec *json.Decoder, keys map[string]bool, depth int) error {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errors.New("syntax error")
		}
		k, ok := tok.(string)
		if !ok {
			return errors.New("syntax error")
		}
		if keys[k] {
			return errors.New("duplicate member")
		}
		keys[k] = true
		if err := scanValue(dec, depth); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("syntax error")
	}
	return nil
}

func scanValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return errors.New("syntax error")
	}
	switch t := tok.(type) {
	case nil:
		return errors.New("null value")
	case json.Delim:
		if depth >= maxDepth {
			return errors.New("nested too deeply")
		}
		switch t {
		case '{':
			return scanMembers(dec, map[string]bool{}, depth+1)
		case '[':
			for dec.More() {
				if err := scanValue(dec, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return errors.New("syntax error")
			}
		}
	}
	return nil
}

var (
	idRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	nonceRe    = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]{1,256}$`)
	edgeNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func checkID(name, v string) error {
	if !idRe.MatchString(v) {
		return fail(CodeMalformed, "%s is not a valid identifier", name)
	}
	return nil
}

func checkServerID(v string) error {
	if !uuidRe.MatchString(v) {
		return fail(CodeMalformed, "server_id is not a canonical uuid")
	}
	return nil
}

func checkTime(name string, t int64) error {
	if t < 0 || t > maxTime {
		return fail(CodeMalformed, "%s out of range", name)
	}
	return nil
}

// ValidNonce reports whether s has the syntax of a server nonce.
func ValidNonce(s string) bool { return nonceRe.MatchString(s) }

// ValidID reports whether s has the syntax of jti, run_id or ins_id.
func ValidID(s string) bool { return idRe.MatchString(s) }
