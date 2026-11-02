package enrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/seawise/client/internal/store"
)

// Device API paths used by enrolment.
const (
	PathEnroll   = "/device/v2/enroll"
	PathConfirm  = "/device/v2/enroll/confirm"
	PathIdentity = "/device/v2/identity"
)

var errAnswer = errors.New("malformed answer")

// strictStrings decodes a JSON object whose members are all strings:
// every required member present, nothing outside required and optional,
// no duplicates, valid UTF-8, nothing after the object.
func strictStrings(raw []byte, required []string, optional ...string) (map[string]string, error) {
	if !utf8.Valid(raw) {
		return nil, errAnswer
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errAnswer
	}
	out := map[string]string{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errAnswer
		}
		name, ok := t.(string)
		if !ok || (!slices.Contains(required, name) && !slices.Contains(optional, name)) {
			return nil, errAnswer
		}
		if _, dup := out[name]; dup {
			return nil, errAnswer
		}
		v, err := dec.Token()
		if err != nil {
			return nil, errAnswer
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

// refusal is the {error, code} body of a refused call; anything else
// reads as empty.
type refusal struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func parseRefusal(raw []byte) refusal {
	var r refusal
	if json.Unmarshal(raw, &r) != nil {
		return refusal{}
	}
	return r
}

// outcome is what one answer means for the enrolment.
type outcome struct {
	kind   kind
	hold   string // kindHold
	reason string // kindRetry: short, safe to show
}

type kind int

const (
	kindOK kind = iota
	kindRetry
	kindHold
	kindUnknownKey
)

func retry(reason string) outcome { return outcome{kind: kindRetry, reason: reason} }
func hold(reason string) outcome  { return outcome{kind: kindHold, hold: reason} }

// classify maps a non-200 answer of path to its outcome.
func classify(path string, status int, body []byte) outcome {
	r := parseRefusal(body)
	switch {
	case status == http.StatusTooManyRequests:
		return retry("rate limited")
	case status >= 500 || status == http.StatusNotFound:
		return retry("device API unavailable (status " + strconv.Itoa(status) + ")")
	}
	if status == http.StatusUnauthorized && r.Error == "invalid_proof" {
		switch {
		case r.Code == "key_revoked" && path != PathEnroll:
			return hold(store.HoldKeyRevoked)
		case r.Code == "invalid_proof" && path != PathEnroll:
			return outcome{kind: kindUnknownKey}
		}
		return retry("proof refused: " + safeCode(r.Code))
	}
	if status == http.StatusUnauthorized && r.Error == "use_dpop_nonce" {
		return retry("server nonce refused")
	}
	switch path {
	case PathEnroll:
		switch {
		case status == http.StatusUnauthorized && r.Error == "invalid_token":
			return hold(store.HoldInvalidToken)
		case status == http.StatusConflict && r.Error == "already_enrolled":
			return hold(store.HoldAlreadyEnrolled)
		case status == http.StatusBadRequest && r.Error == "invalid_key":
			return hold(store.HoldBadKey)
		case status == http.StatusForbidden && r.Error == "repair_required":
			return hold(store.HoldRepairRequired)
		case status == http.StatusBadRequest && r.Error == "invalid_request":
			return hold(store.HoldInvalidRequest)
		}
	case PathConfirm:
		switch {
		case status == http.StatusConflict && r.Error == "not_enrolled":
			return hold(store.HoldNotEnrolled)
		case status == http.StatusBadRequest && r.Error == "invalid_request":
			return hold(store.HoldSwitchRefused)
		}
	}
	return retry("unexpected answer (status " + strconv.Itoa(status) + ")")
}

// safeCode keeps a server code printable and short before it is shown.
func safeCode(c string) string {
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
