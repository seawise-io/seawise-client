// Package claims checks the payloads of the signed documents that travel on
// seawise-tunnel/1 (RouteSet, signed time and device state, protocol flags)
// and the binding of a relayed device call to its DPoP proof. Signature
// verification stays with the consumer's strict JWS verifier; these
// functions take the verified payload.
package claims

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"
)

const (
	maxSafeInt = 1<<53 - 1
	maxDepth   = 8
)

// Code classifies a claims error.
type Code string

const (
	CodeMalformed     Code = "malformed"
	CodeTooLarge      Code = "too_large"
	CodeWrongEdge     Code = "wrong_edge"
	CodeWrongServer   Code = "wrong_server"
	CodeWrongSession  Code = "wrong_session"
	CodeRollback      Code = "rollback"
	CodeTooManyRoutes Code = "too_many_routes"
	CodeNonceMismatch Code = "nonce_mismatch"
	CodeWrongHTM      Code = "wrong_htm"
	CodeWrongHTU      Code = "wrong_htu"
	CodeBodyMismatch  Code = "body_mismatch"
	CodeUseNonce      Code = "use_dpop_nonce"
	CodeWrongKey      Code = "wrong_key"
)

// Error is a claims error.
type Error struct{ Code Code }

func (e *Error) Error() string { return "tunnelwire claims: " + string(e.Code) }

func fail(c Code) error { return &Error{Code: c} }

// CodeOf returns the code of a claims error, or "".
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// decodeObject decodes a JSON object into v: valid UTF-8, no duplicate
// member at any depth, no null, every required member present, no member
// outside required and optional, exact member-name case, nothing after the
// object.
func decodeObject(b []byte, v any, required []string, optional ...string) error {
	if !utf8.Valid(b) {
		return fail(CodeMalformed)
	}
	keys, err := scanObject(b)
	if err != nil {
		return fail(CodeMalformed)
	}
	for _, k := range required {
		if !keys[k] {
			return fail(CodeMalformed)
		}
	}
	for k := range keys {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return fail(CodeMalformed)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fail(CodeMalformed)
	}
	return nil
}

func scanObject(b []byte) (map[string]bool, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
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
			return err
		}
		k := tok.(string)
		if keys[k] {
			return errors.New("duplicate member")
		}
		keys[k] = true
		if err := scanValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func scanValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case nil:
		return errors.New("null")
	case json.Delim:
		if depth >= maxDepth {
			return errors.New("too deep")
		}
		if t == '{' {
			return scanMembers(dec, map[string]bool{}, depth+1)
		}
		for dec.More() {
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}

func safeInt(v int64) bool { return v >= 0 && v <= maxSafeInt }
