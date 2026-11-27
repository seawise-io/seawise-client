package protocol

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"net"
	"net/url"
	"strings"
)

// DPoPClaims are the claims of a request proof.
type DPoPClaims struct {
	JTI        string `json:"jti"`
	HTM        string `json:"htm"`
	HTU        string `json:"htu"`
	IAT        int64  `json:"iat"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
}

var dpopMembers = []string{"jti", "htm", "htu", "iat", "nonce", "body_sha256"}

// DPoPRequest is the request a proof must match, as the server received it.
type DPoPRequest struct {
	Method string
	URL    string
	Body   []byte
}

// DPoPResult is a verified proof.
type DPoPResult struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Claims    DPoPClaims
}

// CanonicalHTU returns the form of a request URL that a proof's htu must
// equal: lower-case scheme and host, default port dropped, path as sent or
// "/", the raw query exactly as sent, no userinfo or fragment. Binding the
// query departs from RFC 9449, which leaves it out.
func CanonicalHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fail(CodeMalformed, "url does not parse")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Opaque != "" || u.User != nil || u.Host == "" {
		return "", fail(CodeMalformed, "url must be absolute http(s) without userinfo")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fail(CodeMalformed, "url has no host")
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	switch {
	case port != "":
		host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		path += "?" + u.RawQuery
	}
	return scheme + "://" + host + path, nil
}

// BodyDigest returns the body_sha256 value for body.
func BodyDigest(body []byte) string {
	d := sha256.Sum256(body)
	return b64Encode(d[:])
}

// NewDPoP signs a proof for a request.
func NewDPoP(s crypto.Signer, method, rawURL string, body []byte, nonce, jti string, iat int64) (string, error) {
	htu, err := CanonicalHTU(rawURL)
	if err != nil {
		return "", err
	}
	c := DPoPClaims{JTI: jti, HTM: method, HTU: htu, IAT: iat, Nonce: nonce, BodySHA256: BodyDigest(body)}
	if err := c.check(); err != nil {
		return "", err
	}
	return signJWS(s, TypDPoP, true, c)
}

func (c *DPoPClaims) check() error {
	if err := checkID("jti", c.JTI); err != nil {
		return err
	}
	if c.HTM == "" || len(c.HTM) > 32 {
		return fail(CodeMalformed, "htm is empty or too long")
	}
	if err := checkTime("iat", c.IAT); err != nil {
		return err
	}
	if !ValidNonce(c.Nonce) {
		return fail(CodeBadNonce, "nonce syntax")
	}
	if d, err := b64Decode(c.BodySHA256); err != nil || len(d) != sha256.Size {
		return fail(CodeMalformed, "body_sha256 is not a base64url SHA-256")
	}
	return nil
}

// VerifyDPoP checks a proof against the request. nonceValid reports whether
// the server issued the nonce and it is still fresh. claimJTI records the
// (key ID, jti) pair and returns false if it was already recorded; it is
// called only after every other check passed.
func VerifyDPoP(proof string, req DPoPRequest, nonceValid func(string) bool, claimJTI func(kid, jti string) bool) (*DPoPResult, error) {
	t, err := parseJWS(proof, TypDPoP, "jwk", maxTokenSize)
	if err != nil {
		return nil, err
	}
	pub, err := parseJWK(t.jwk)
	if err != nil {
		return nil, err
	}
	if err := t.verify(pub); err != nil {
		return nil, err
	}
	var c DPoPClaims
	if err := decodeObject(t.payload, &c, dpopMembers); err != nil {
		return nil, err
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	if c.HTM != req.Method {
		return nil, fail(CodeWrongHTM, "htm does not match the request method")
	}
	htu, err := CanonicalHTU(req.URL)
	if err != nil {
		return nil, err
	}
	if c.HTU != htu {
		return nil, fail(CodeWrongHTU, "htu does not match the request url")
	}
	want := sha256.Sum256(req.Body)
	got, _ := b64Decode(c.BodySHA256)
	if !bytes.Equal(got, want[:]) {
		return nil, fail(CodeBodyMismatch, "body digest does not match")
	}
	if !nonceValid(c.Nonce) {
		return nil, fail(CodeBadNonce, "nonce unknown or expired")
	}
	kid := KeyID(pub)
	if !claimJTI(kid, c.JTI) {
		return nil, fail(CodeReplayed, "jti already used")
	}
	return &DPoPResult{KeyID: kid, PublicKey: pub, Claims: c}, nil
}
