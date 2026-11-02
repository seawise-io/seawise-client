package store

import (
	"fmt"
	"time"
)

// Enrolment phases of a 1.x account moving to its device key.
const (
	PhasePending  = "pending"
	PhaseEnrolled = "enrolled"
	PhaseSwitched = "switched"
)

// Enrolment hold reasons.
const (
	HoldInvalidToken    = "invalid_token"
	HoldAlreadyEnrolled = "already_enrolled"
	HoldBadKey          = "bad_key"
	HoldRepairRequired  = "repair_required"
	HoldInvalidRequest  = "invalid_request"
	HoldIdentity        = "identity_mismatch"
	HoldKeyRevoked      = "key_revoked"
	HoldNotEnrolled     = "not_enrolled"
	HoldSwitchRefused   = "switch_refused"
	HoldTokenUnusable   = "token_unusable"
	HoldServerID        = "server_id_invalid"
	HoldKeyLost         = "key_lost"
	HoldKeyUnknown      = "key_unknown"
	HoldInsecureOrigin  = "insecure_origin"
)

var enrolmentHolds = map[string]bool{
	HoldInvalidToken: true, HoldAlreadyEnrolled: true, HoldBadKey: true, HoldRepairRequired: true,
	HoldInvalidRequest: true, HoldIdentity: true, HoldKeyRevoked: true, HoldNotEnrolled: true,
	HoldSwitchRefused: true, HoldTokenUnusable: true, HoldServerID: true, HoldKeyLost: true, HoldKeyUnknown: true, HoldInsecureOrigin: true,
}

// Enrolment records how far the paired server's move from its 1.x token
// to the device key has gone. A hold never changes anything else.
type Enrolment struct {
	ServerID   string     `json:"server_id"`
	Phase      string     `json:"phase"`
	KeyID      string     `json:"key_id,omitempty"`
	DeviceID   string     `json:"device_id,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	SwitchedAt *time.Time `json:"switched_at,omitempty"`
	Hold       string     `json:"hold,omitempty"`
	HoldAt     *time.Time `json:"hold_at,omitempty"`
}

// EnrolmentFor returns the record for the paired server, or nil.
func (st State) EnrolmentFor() *Enrolment {
	if st.Account == nil || st.Enrolment == nil || st.Enrolment.ServerID != st.Account.ServerID {
		return nil
	}
	return st.Enrolment
}

// EnrolmentNeeded reports whether the paired server has not switched to
// the device key; until then it holds its 1.x token.
func (st State) EnrolmentNeeded(_ Secrets) bool {
	if st.Account == nil {
		return false
	}
	e := st.EnrolmentFor()
	return e == nil || e.Phase != PhaseSwitched
}

func validateEnrolment(e *Enrolment) error {
	if e == nil {
		return nil
	}
	switch {
	case e.ServerID == "":
		return fmt.Errorf("%w: enrolment server_id required", ErrInvalid)
	case e.Phase != PhasePending && e.Phase != PhaseEnrolled && e.Phase != PhaseSwitched:
		return fmt.Errorf("%w: unknown enrolment phase", ErrInvalid)
	case e.Phase != PhasePending && e.KeyID == "":
		return fmt.Errorf("%w: enrolment key_id required", ErrInvalid)
	case e.Hold != "" && !enrolmentHolds[e.Hold]:
		return fmt.Errorf("%w: unknown enrolment hold", ErrInvalid)
	}
	return nil
}

func cloneEnrolment(e *Enrolment) *Enrolment {
	if e == nil {
		return nil
	}
	out := *e
	for _, p := range []**time.Time{&out.EnrolledAt, &out.SwitchedAt, &out.HoldAt} {
		if *p != nil {
			t := **p
			*p = &t
		}
	}
	return &out
}
