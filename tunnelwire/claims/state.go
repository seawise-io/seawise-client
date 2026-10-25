package claims

import (
	"encoding/base64"
	"regexp"
)

// TypTime is the signed time and device state JWS type.
const TypTime = "sw-time+jwt"

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

// Device and account statuses in a signed heartbeat.
const (
	DeviceActive       = "active"
	DeviceRevoked      = "revoked"
	DeviceCompromised  = "compromised"
	DevicePending      = "pending"
	DeviceEnrolPending = "enrol_pending"
	AccountActive      = "active"
	AccountSuspended   = "suspended"
	AccountBanned      = "banned"
)

// SignedState is a verified signed time statement. HasState is set when it
// also carries the device state claims; only then may it move the agent to
// HOLD or allow V1.
type SignedState struct {
	ServerID      string `json:"server_id"`
	Time          int64  `json:"time"`
	Nonce         string `json:"nonce"`
	HasState      bool   `json:"-"`
	DeviceStatus  string `json:"device_status,omitempty"`
	AccountStatus string `json:"account_status,omitempty"`
	V1TokenLive   bool   `json:"v1_token_live,omitempty"`
}

var stateMembers = []string{"device_status", "account_status", "v1_token_live"}

// CheckSignedState decodes a verified control-key time statement and binds
// it to the server and the nonce the agent just sent. The state claims are
// all present or all absent.
func CheckSignedState(payload []byte, serverID, nonce string) (*SignedState, error) {
	var st struct {
		ServerID      string  `json:"server_id"`
		Time          int64   `json:"time"`
		Nonce         string  `json:"nonce"`
		DeviceStatus  *string `json:"device_status"`
		AccountStatus *string `json:"account_status"`
		V1TokenLive   *bool   `json:"v1_token_live"`
	}
	if err := decodeObject(payload, &st, []string{"server_id", "time", "nonce"}, stateMembers...); err != nil {
		return nil, err
	}
	if !ValidUUID(st.ServerID) || !safeInt(st.Time) || !idRe.MatchString(st.Nonce) {
		return nil, fail(CodeMalformed)
	}
	out := &SignedState{ServerID: st.ServerID, Time: st.Time, Nonce: st.Nonce}
	n := 0
	for _, p := range []bool{st.DeviceStatus != nil, st.AccountStatus != nil, st.V1TokenLive != nil} {
		if p {
			n++
		}
	}
	switch n {
	case 0:
	case 3:
		switch *st.DeviceStatus {
		case DeviceActive, DeviceRevoked, DeviceCompromised, DevicePending, DeviceEnrolPending:
		default:
			return nil, fail(CodeMalformed)
		}
		switch *st.AccountStatus {
		case AccountActive, AccountSuspended, AccountBanned:
		default:
			return nil, fail(CodeMalformed)
		}
		out.HasState, out.DeviceStatus, out.AccountStatus, out.V1TokenLive = true, *st.DeviceStatus, *st.AccountStatus, *st.V1TokenLive
	default:
		return nil, fail(CodeMalformed)
	}
	if out.ServerID != serverID {
		return nil, fail(CodeWrongServer)
	}
	if out.Nonce != nonce {
		return nil, fail(CodeNonceMismatch)
	}
	return out, nil
}

// TimeNonce returns the nonce string a signed time must carry for
// HelloBody.time_nonce.
func TimeNonce(timeNonce []byte) string { return base64.RawURLEncoding.EncodeToString(timeNonce) }

// Holds reports whether a signed state confirms a revoked or compromised
// key or an account that is not in good standing.
func (s *SignedState) Holds() bool {
	return s.HasState && (s.DeviceStatus == DeviceRevoked || s.DeviceStatus == DeviceCompromised || s.AccountStatus != AccountActive)
}

// Clears reports whether a signed state shows an active key and an account
// in good standing.
func (s *SignedState) Clears() bool {
	return s.HasState && s.DeviceStatus == DeviceActive && s.AccountStatus == AccountActive
}
