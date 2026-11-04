package claims

import (
	"encoding/base64"
	"regexp"
)

// JWS types of the control-key time and device state statements.
const (
	TypTime  = "sw-time+jwt"
	TypState = "sw-state+jwt"
)

var (
	idRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	kidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// Device and account statuses in a signed state.
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

// SignedTime is a verified time-only statement.
type SignedTime struct {
	ServerID string `json:"server_id"`
	Time     int64  `json:"time"`
	Nonce    string `json:"nonce"`
}

// SignedState is a verified device state statement; only it may move the
// agent to HOLD or out of a signed one.
type SignedState struct {
	ServerID      string `json:"server_id"`
	KeyID         string `json:"key_id"`
	Time          int64  `json:"time"`
	Nonce         string `json:"nonce"`
	DeviceStatus  string `json:"device_status"`
	AccountStatus string `json:"account_status"`
}

// CheckSignedTime decodes a verified sw-time+jwt payload and binds it to
// the server and the nonce the agent sent.
func CheckSignedTime(payload []byte, serverID, nonce string) (*SignedTime, error) {
	var st SignedTime
	if err := decodeObject(payload, &st, []string{"server_id", "time", "nonce"}); err != nil {
		return nil, err
	}
	if !ValidUUID(st.ServerID) || !safeInt(st.Time) || !idRe.MatchString(st.Nonce) {
		return nil, fail(CodeMalformed)
	}
	if st.ServerID != serverID {
		return nil, fail(CodeWrongServer)
	}
	if st.Nonce != nonce {
		return nil, fail(CodeNonceMismatch)
	}
	return &st, nil
}

// CheckSignedState decodes a verified sw-state+jwt payload and binds it to
// the server, the agent's own key and the nonce it just sent. Every claim
// is required: a statement without the state is refused.
func CheckSignedState(payload []byte, serverID, keyID, nonce string) (*SignedState, error) {
	var st SignedState
	if err := decodeObject(payload, &st, []string{"server_id", "key_id", "time", "nonce", "device_status", "account_status"}); err != nil {
		return nil, err
	}
	if !ValidUUID(st.ServerID) || !kidRe.MatchString(st.KeyID) || !safeInt(st.Time) || !idRe.MatchString(st.Nonce) {
		return nil, fail(CodeMalformed)
	}
	switch st.DeviceStatus {
	case DeviceActive, DeviceRevoked, DeviceCompromised, DevicePending, DeviceEnrolPending:
	default:
		return nil, fail(CodeMalformed)
	}
	switch st.AccountStatus {
	case AccountActive, AccountSuspended, AccountBanned:
	default:
		return nil, fail(CodeMalformed)
	}
	if st.ServerID != serverID {
		return nil, fail(CodeWrongServer)
	}
	if st.KeyID != keyID {
		return nil, fail(CodeWrongKey)
	}
	if st.Nonce != nonce {
		return nil, fail(CodeNonceMismatch)
	}
	return &st, nil
}

// TimeNonce returns the nonce string a signed time must carry for
// HelloBody.time_nonce.
func TimeNonce(timeNonce []byte) string { return base64.RawURLEncoding.EncodeToString(timeNonce) }

// Holds reports whether the state confirms a revoked or compromised key or
// an account that is not in good standing.
func (s *SignedState) Holds() bool {
	return s.DeviceStatus == DeviceRevoked || s.DeviceStatus == DeviceCompromised || s.AccountStatus != AccountActive
}

// Clears reports whether the state shows an active key and an account in
// good standing.
func (s *SignedState) Clears() bool {
	return s.DeviceStatus == DeviceActive && s.AccountStatus == AccountActive
}
