package devicecall

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"unicode/utf8"
)

var errAnswer = errors.New("malformed answer")

// StrictStrings decodes a JSON object whose members are strings: every
// required member present and a string, optional members a string or
// null (null reads as absent), nothing else, no duplicates, valid UTF-8,
// nothing after the object.
func StrictStrings(raw []byte, required []string, optional ...string) (map[string]string, error) {
	if !utf8.Valid(raw) {
		return nil, errAnswer
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errAnswer
	}
	out := map[string]string{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errAnswer
		}
		name, ok := t.(string)
		isOptional := slices.Contains(optional, name)
		if !ok || (!slices.Contains(required, name) && !isOptional) || seen[name] {
			return nil, errAnswer
		}
		seen[name] = true
		v, err := dec.Token()
		if err != nil {
			return nil, errAnswer
		}
		if v == nil && isOptional {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return nil, errAnswer
		}
		out[name] = s
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errAnswer
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errAnswer
	}
	for _, r := range required {
		if _, ok := out[r]; !ok {
			return nil, errAnswer
		}
	}
	return out, nil
}

// Refusal is the {error, code} body of a refused call; anything else
// reads as empty.
type Refusal struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func ParseRefusal(raw []byte) Refusal {
	var r Refusal
	if json.Unmarshal(raw, &r) != nil {
		return Refusal{}
	}
	return r
}

// SafeCode keeps a server code printable and short before it is shown.
func SafeCode(c string) string {
	if c == "" || len(c) > 32 {
		return "unknown"
	}
	for _, r := range c {
		if !(r == '_' || (r >= 'a' && r <= 'z')) {
			return "unknown"
		}
	}
	return c
}
