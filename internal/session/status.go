package session

import (
	"time"

	"github.com/seawise-io/seawise-client/tunnelwire/ladder"
)

// Status is the tunnel as the local UI and status API show it.
type Status struct {
	State     string    `json:"state"`
	Hold      string    `json:"hold,omitempty"`
	HoldText  string    `json:"hold_text,omitempty"`
	Carriage  string    `json:"carriage"`
	Up        bool      `json:"up"`
	Edge      string    `json:"edge,omitempty"`
	SessionID string    `json:"session_id,omitempty"`
	Proxied   bool      `json:"proxied,omitempty"`
	LastKnown bool      `json:"last_known_address,omitempty"`
	Since     time.Time `json:"since"`
	// NextDial is the latest time of the next scheduled dial, if any.
	NextDial        time.Time `json:"next_dial,omitzero"`
	LastError       string    `json:"last_error,omitempty"`
	FlagsGeneration int64     `json:"flags_generation"`
	FlagsMode       string    `json:"flags_mode"`
	SignedTime      int64     `json:"signed_time,omitempty"`
	MinVersion      string    `json:"min_version,omitempty"`
	Supersedes      int       `json:"supersedes,omitempty"`
	FlagsRollbacks  int       `json:"flags_rollbacks,omitempty"`
}

// HoldText is what the UI shows for a hold reason.
func HoldText(reason string) string {
	switch reason {
	case ladder.HoldUpdate:
		return "update required"
	case ladder.HoldMaintenance, ladder.HoldFlagsOff:
		return "maintenance"
	case ladder.HoldTooManyRoutes:
		return "too many apps"
	case ladder.HoldRevoked:
		return "device revoked"
	case ladder.HoldSuspended:
		return "account suspended"
	case ladder.HoldRepair:
		return "repair needed"
	}
	return ""
}
