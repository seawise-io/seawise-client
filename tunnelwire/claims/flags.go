package claims

import (
	"crypto/sha256"
	"encoding/base64"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// Flags JWS type and caps.
const (
	TypFlags     = "sw-tunnel-flags+jws"
	MaxFlagsList = 128
	SaltSize     = 16
)

// Flags is the verified payload of the control-key signed protocol flags.
type Flags struct {
	Generation      int64    `json:"generation"`
	Global          string   `json:"global"`
	RolloutPermille int64    `json:"rollout_permille"`
	Salt            string   `json:"salt"`
	Allow           []string `json:"allow"`
	Deny            []string `json:"deny"`
	IAT             int64    `json:"iat"`
	salt            []byte
}

// CheckFlagsSize refuses a flags JWS over its cap.
func CheckFlagsSize(jws string) error {
	if len(jws) > wire.MaxFlags {
		return fail(CodeTooLarge)
	}
	return nil
}

func validHashList(l []string) bool {
	if len(l) > MaxFlagsList {
		return false
	}
	seen := map[string]bool{}
	for _, h := range l {
		b, err := base64.RawURLEncoding.Strict().DecodeString(h)
		if err != nil || len(b) != sha256.Size || seen[h] {
			return false
		}
		seen[h] = true
	}
	return true
}

// ParseFlags decodes a verified flags payload.
func ParseFlags(payload []byte) (*Flags, error) {
	var f Flags
	if err := decodeObject(payload, &f, []string{"generation", "global", "rollout_permille", "salt", "allow", "deny", "iat"}); err != nil {
		return nil, err
	}
	salt, err := base64.RawURLEncoding.Strict().DecodeString(f.Salt)
	if err != nil || len(salt) != SaltSize || f.Generation < 1 || !safeInt(f.Generation) || !safeInt(f.IAT) ||
		(f.Global != "on" && f.Global != "off") || f.RolloutPermille < 0 || f.RolloutPermille > 1000 ||
		!validHashList(f.Allow) || !validHashList(f.Deny) {
		return nil, fail(CodeMalformed)
	}
	f.salt = salt
	return &f, nil
}

func digest(salt, serverID []byte) [32]byte {
	return sha256.Sum256(append(append([]byte{}, salt...), serverID...))
}

// HashedID returns base64url(SHA-256(salt || server_id)), server_id being
// the 16 UUID bytes.
func HashedID(salt, serverID []byte) string {
	d := digest(salt, serverID)
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Mode evaluates the flags for one server: global off or a deny entry gives
// OFF, anything else ON. allow and rollout_permille are parsed for format
// compatibility and have no effect.
func (f *Flags) Mode(serverID []byte) pb.ProtocolMode {
	if f.Global == "off" || contains(f.Deny, HashedID(f.salt, serverID)) {
		return pb.ProtocolMode_OFF
	}
	return pb.ProtocolMode_ON
}

// AcceptNewer refuses a document whose generation is not above the last
// accepted one.
func AcceptNewer(lastGeneration int64, f *Flags) error {
	if f.Generation <= lastGeneration {
		return fail(CodeRollback)
	}
	return nil
}
