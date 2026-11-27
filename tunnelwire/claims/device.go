package claims

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// DPoPClaims are the claims of a device request proof.
type DPoPClaims struct {
	JTI        string `json:"jti"`
	HTM        string `json:"htm"`
	HTU        string `json:"htu"`
	IAT        int64  `json:"iat"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
}

// ParseDPoPClaims decodes the payload of a verified DPoP proof.
func ParseDPoPClaims(payload []byte) (*DPoPClaims, error) {
	var c DPoPClaims
	if err := decodeObject(payload, &c, []string{"jti", "htm", "htu", "iat", "nonce", "body_sha256"}); err != nil {
		return nil, err
	}
	if !idRe.MatchString(c.JTI) || !safeInt(c.IAT) || c.Nonce == "" {
		return nil, fail(CodeMalformed)
	}
	return &c, nil
}

// BodyDigest returns the body_sha256 value for body.
func BodyDigest(body []byte) string {
	d := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// CheckRelayedProof binds a relayed call to its proof as device-api does:
// the proof's key is the one registered for the session's server, htm and
// htu are the call's HTTPS twin under origin, body_sha256 covers
// DeviceCall.body, and the nonce is the current one (else the RFC 9449
// use_dpop_nonce answer).
func CheckRelayedProof(call *pb.DeviceCall, origin string, proofKeyID, serverKeyID string, c *DPoPClaims, nonce string) error {
	method, path, err := wire.TwinPath(call.GetMethod(), call.GetPathSuffix())
	if err != nil {
		return fail(CodeMalformed)
	}
	switch {
	case proofKeyID != serverKeyID:
		return fail(CodeWrongKey)
	case c.HTM != method:
		return fail(CodeWrongHTM)
	case c.HTU != strings.TrimSuffix(origin, "/")+path:
		return fail(CodeWrongHTU)
	case c.BodySHA256 != BodyDigest(call.GetBody()):
		return fail(CodeBodyMismatch)
	case c.Nonce != nonce:
		return fail(CodeUseNonce)
	}
	return nil
}

// DedupeScope is the key under which device-api stores a call's result.
func DedupeScope(serverID string, m pb.DeviceMethod, path string, key []byte) string {
	return serverID + " " + m.String() + " " + path + " " + hex.EncodeToString(key)
}

// Stored is a dedupe entry.
type Stored struct {
	BodySHA256 [32]byte
	Status     int
	Body       []byte
}

// Outcome is what device-api does with a call that passed its proof check.
type Outcome string

const (
	Execute  Outcome = "execute"
	Replay   Outcome = "replay"
	Mismatch Outcome = "idempotency_mismatch"
)

// Dedupe decides a call against its stored entry, if any: the first call
// executes, a repeat with the same body gets the stored response, a repeat
// with another body is 409 idempotency_mismatch.
func Dedupe(stored *Stored, body []byte) Outcome {
	if stored == nil {
		return Execute
	}
	if sha256.Sum256(body) == stored.BodySHA256 {
		return Replay
	}
	return Mismatch
}
