package enrol

import (
	"net/http"
	"strconv"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/store"
)

// Device API paths used by enrolment.
const (
	PathEnroll   = "/device/v2/enroll"
	PathConfirm  = "/device/v2/enroll/confirm"
	PathIdentity = "/device/v2/identity"
)

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
	r := devicecall.ParseRefusal(body)
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
		return retry("proof refused: " + devicecall.SafeCode(r.Code))
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
