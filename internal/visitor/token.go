// Package visitor checks the visitor tokens the edge attaches to each data
// stream: a sw-visitor+jwt signed by a SeaWise visitor key and, while the
// edge serves a session past its expiry, a sw-stale-ok+jws bound signed by
// an edge key. Both keys come only from the verified key set. The rules and
// reason codes are the platform's, shared through testdata/vectors.
package visitor

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
)

// Reason is why a token was refused.
type Reason string

const (
	TooLarge     Reason = "too_large"
	Malformed    Reason = "malformed"
	BadAlg       Reason = "bad_alg"
	BadTyp       Reason = "bad_typ"
	BadSignature Reason = "bad_signature"
	UnknownKey   Reason = "unknown_key"
	Expired      Reason = "expired"
	NotYetValid  Reason = "not_yet_valid"
	NotBound     Reason = "not_bound"
)

// Error is a refusal. Its text never quotes the input.
type Error struct {
	Reason Reason
	detail string
}

func (e *Error) Error() string { return "visitor token: " + string(e.Reason) + ": " + e.detail }

func fail(r Reason, detail string) error { return &Error{Reason: r, detail: detail} }

// ReasonOf returns the reason of a refusal from this package, or "".
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// Token types and size caps.
const (
	TypVisitor = "sw-visitor+jwt"
	TypStaleOk = "sw-stale-ok+jws"
	MaxVisitor = 2048
	MaxStaleOk = 512
	// maxHeaderSegment bounds the header segment before it is decoded.
	maxHeaderSegment = 1024
	// staleSkew is the tolerance on stale-ok times.
	staleSkew = 30
	// StaleWindow is how far past a token's exp a stale-ok bound reaches.
	StaleWindow = 1800
)

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

var b64url = base64.RawURLEncoding.Strict()

// b64Decode decodes canonical unpadded base64url only. The alphabet is
// checked first because the decoder skips CR and LF.
func b64Decode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(b64Alphabet, s[i]) < 0 {
			return nil, fail(Malformed, "not canonical base64url")
		}
	}
	b, err := b64url.DecodeString(s)
	if err != nil {
		return nil, fail(Malformed, "not canonical base64url")
	}
	return b, nil
}

// verified checks size, segments, encoding, header and signature, and
// returns the payload and the signing key's entry.
func verified(token, typ string, maxSize int, lookup func(kid string) (key, bool)) ([]byte, key, error) {
	if len(token) > maxSize {
		return nil, key{}, fail(TooLarge, "token exceeds the size limit")
	}
	if strings.Count(token, ".") != 2 {
		return nil, key{}, fail(Malformed, "want 3 segments")
	}
	if strings.IndexByte(token, '.') > maxHeaderSegment {
		return nil, key{}, fail(Malformed, "header segment too long")
	}
	parts := strings.SplitN(token, ".", 3)
	hb, err := b64Decode(parts[0])
	if err != nil {
		return nil, key{}, err
	}
	h, err := parseObject(hb, []string{"alg"}, []string{"typ", "kid"})
	if err != nil {
		return nil, key{}, err
	}
	alg, algOK := h["alg"].(string)
	typV, hasTyp := h["typ"]
	gotTyp, typOK := typV.(string)
	kidV, hasKid := h["kid"]
	kid, kidOK := kidV.(string)
	if !algOK || (hasTyp && !typOK) || (hasKid && !kidOK) {
		return nil, key{}, fail(Malformed, "header member has the wrong type")
	}
	if alg != "EdDSA" {
		return nil, key{}, fail(BadAlg, "alg must be EdDSA")
	}
	if gotTyp != typ {
		return nil, key{}, fail(BadTyp, "wrong typ")
	}
	if kid == "" {
		return nil, key{}, fail(Malformed, "header must carry kid")
	}
	payload, err := b64Decode(parts[1])
	if err != nil {
		return nil, key{}, err
	}
	sig, err := b64Decode(parts[2])
	if err != nil {
		return nil, key{}, err
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, key{}, fail(Malformed, "signature must be 64 bytes")
	}
	k, ok := lookup(kid)
	if !ok {
		return nil, key{}, fail(UnknownKey, "kid is not a key of this kind")
	}
	// crypto/ed25519 refuses S at or above the group order.
	if !ed25519.Verify(k.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, key{}, fail(BadSignature, "signature does not verify")
	}
	return payload, k, nil
}

var (
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	edgeIDRE = regexp.MustCompile(`^edge-[a-z]+-[a-z]+-[0-9]{1,4}$`)
)

func isUUID(v any) bool {
	s, ok := v.(string)
	return ok && uuidRE.MatchString(s)
}

func num(v any) int64 { return int64(v.(float64)) }

func str(v any) string {
	s, _ := v.(string)
	return s
}

func exactly(o map[string]any, members []string) bool {
	if len(o) != len(members) {
		return false
	}
	for _, m := range members {
		if _, ok := o[m]; !ok {
			return false
		}
	}
	return true
}

// Token is a visitor token's claims: a user session's (Kind "user": Sub,
// Epoch) or a share-link session's (Kind "share_link": Jti).
type Token struct {
	Kind  string
	Sid   string
	Sub   string
	Epoch int64
	Jti   string
	Aud   string
	Acct  string
	Gen   int64
	Av    int64
	Iat   int64
	Exp   int64
}

var (
	tokenBase    = []string{"sid", "aud", "acct", "gen", "av", "iat", "exp"}
	userMembers  = []string{"sid", "sub", "epoch", "aud", "acct", "gen", "av", "iat", "exp"}
	shareMembers = []string{"sid", "jti", "aud", "acct", "gen", "av", "iat", "exp"}
)

// VerifyToken verifies a visitor token's signature and claims, not its times.
func VerifyToken(token string, keys *Keys) (*Token, error) {
	payload, _, err := verified(token, TypVisitor, MaxVisitor, keys.visitor)
	if err != nil {
		return nil, err
	}
	c, err := parseObject(payload, tokenBase, []string{"sub", "epoch", "jti"})
	if err != nil {
		return nil, err
	}
	_, user := c["sub"]
	members := shareMembers
	if user {
		members = userMembers
	}
	if !exactly(c, members) {
		return nil, fail(Malformed, "claims must be one format's members")
	}
	if !isUUID(c["sid"]) || !isUUID(c["aud"]) || !isUUID(c["acct"]) || !isCount(c["gen"], 1) || !isCount(c["av"], 0) ||
		!isCount(c["iat"], 0) || !isCount(c["exp"], 0) || num(c["exp"]) < num(c["iat"]) {
		return nil, fail(Malformed, "claim values out of range")
	}
	t := &Token{Kind: "share_link", Sid: str(c["sid"]), Aud: str(c["aud"]), Acct: str(c["acct"]),
		Gen: num(c["gen"]), Av: num(c["av"]), Iat: num(c["iat"]), Exp: num(c["exp"])}
	if user {
		if !isUUID(c["sub"]) || !isCount(c["epoch"], 0) {
			return nil, fail(Malformed, "sub and epoch out of range")
		}
		t.Kind, t.Sub, t.Epoch = "user", str(c["sub"]), num(c["epoch"])
	} else {
		if !isUUID(c["jti"]) {
			return nil, fail(Malformed, "jti must be a uuid")
		}
		t.Jti = str(c["jti"])
	}
	return t, nil
}

// StaleOk is an edge's statement that it serves a session past its expiry.
type StaleOk struct {
	Edge  string
	Aud   string
	Sid   string
	Until int64
	Iat   int64
}

var staleOkMembers = []string{"edge", "aud", "sid", "until", "iat"}

// VerifyStaleOk verifies a stale-ok bound with the edge keys at now
// (seconds): signature, claims, the edge named being the key's owner, and
// times with a 30 s skew.
func VerifyStaleOk(token string, keys *Keys, now int64) (*StaleOk, error) {
	payload, k, err := verified(token, TypStaleOk, MaxStaleOk, keys.edge)
	if err != nil {
		return nil, err
	}
	o, err := parseObject(payload, staleOkMembers, nil)
	if err != nil {
		return nil, err
	}
	if !isCount(o["until"], 0) || !isCount(o["iat"], 0) {
		return nil, fail(Malformed, "claim values out of range")
	}
	c := &StaleOk{Edge: str(o["edge"]), Aud: str(o["aud"]), Sid: str(o["sid"]), Until: num(o["until"]), Iat: num(o["iat"])}
	if len(c.Edge) > 63 || !edgeIDRE.MatchString(c.Edge) || !isUUID(o["aud"]) || !isUUID(o["sid"]) ||
		c.Until <= c.Iat || c.Until-c.Iat > StaleWindow {
		return nil, fail(Malformed, "claim values out of range")
	}
	if k.name != c.Edge {
		return nil, fail(Malformed, "edge is not the key's owner")
	}
	if c.Iat-staleSkew > now {
		return nil, fail(NotYetValid, "issued in the future")
	}
	if now > c.Until+staleSkew {
		return nil, fail(Expired, "expired")
	}
	return c, nil
}

// CheckStaleOk verifies a stale-ok bound for a verified visitor token:
// VerifyStaleOk, then until == exp + StaleWindow and the token's sid and aud.
func CheckStaleOk(header string, t *Token, keys *Keys, now int64) (*StaleOk, error) {
	c, err := VerifyStaleOk(header, keys, now)
	if err != nil {
		return nil, err
	}
	if t == nil || c.Until != t.Exp+StaleWindow || c.Sid != t.Sid || c.Aud != t.Aud {
		return nil, fail(NotBound, "stale-ok is not bound to the visitor token")
	}
	return c, nil
}
