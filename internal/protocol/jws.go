package protocol

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
)

const (
	algEdDSA      = "EdDSA"
	maxTokenSize  = 4096
	maxKeySetSize = 65536
)

// Token types.
const (
	TypDPoP      = "dpop+jwt"
	TypFRP       = "sw-frp+jwt"
	TypRotate    = "sw-rotate+jwt"
	TypRotatePoP = "sw-rotate-pop+jwt"
	TypKeySet    = "sw-keyset+jwt"
	TypInstr     = "sw-instr+jwt"
	TypTime      = "sw-time+jwt"
)

type signHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	JWK *JWK   `json:"jwk,omitempty"`
}

type wireHeader struct {
	Alg string          `json:"alg"`
	Typ string          `json:"typ"`
	Kid string          `json:"kid"`
	JWK json.RawMessage `json:"jwk"`
}

type jws struct {
	kid          string
	jwk          json.RawMessage
	payloadB64   string
	payload      []byte
	signingInput string
	sig          []byte
}

func signerPublic(s crypto.Signer) (ed25519.PublicKey, error) {
	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("signer is not an Ed25519 key")
	}
	return pub, nil
}

// signJWS signs claims with s. withJWK puts the public key in the header
// instead of its key ID.
func signJWS(s crypto.Signer, typ string, withJWK bool, claims any) (string, error) {
	pub, err := signerPublic(s)
	if err != nil {
		return "", err
	}
	h := signHeader{Typ: typ, Alg: algEdDSA}
	if withJWK {
		j := PublicJWK(pub)
		h.JWK = &j
	} else {
		h.Kid = KeyID(pub)
	}
	input := b64Encode(mustJSON(h)) + "." + b64Encode(mustJSON(claims))
	sig, err := s.Sign(nil, []byte(input), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	if len(sig) != ed25519.SignatureSize {
		return "", errors.New("signer returned a malformed signature")
	}
	return input + "." + b64Encode(sig), nil
}

// parseJWS checks size, segments, encoding and the header. keyMember is
// "kid" or "jwk", the one member the format requires. The payload is
// decoded but not parsed and the signature is not checked.
func parseJWS(token, typ, keyMember string, maxSize int) (*jws, error) {
	if len(token) > maxSize {
		return nil, fail(CodeTooLarge, "token exceeds %d bytes", maxSize)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail(CodeMalformed, "want 3 segments, got %d", len(parts))
	}
	hb, err := b64Decode(parts[0])
	if err != nil {
		return nil, fail(CodeMalformed, "header is not base64url")
	}
	var h wireHeader
	if err := decodeObject(hb, &h, []string{"alg"}, "typ", "kid", "jwk"); err != nil {
		return nil, err
	}
	if h.Alg != algEdDSA {
		return nil, fail(CodeBadAlg, "alg must be %s", algEdDSA)
	}
	if h.Typ != typ {
		return nil, fail(CodeBadTyp, "typ must be %s", typ)
	}
	switch keyMember {
	case "kid":
		if h.JWK != nil || h.Kid == "" {
			return nil, fail(CodeMalformed, "header must carry kid only")
		}
	case "jwk":
		if h.Kid != "" || h.JWK == nil {
			return nil, fail(CodeMalformed, "header must carry jwk only")
		}
	}
	payload, err := b64Decode(parts[1])
	if err != nil {
		return nil, fail(CodeMalformed, "payload is not base64url")
	}
	sig, err := b64Decode(parts[2])
	if err != nil {
		return nil, fail(CodeMalformed, "signature is not base64url")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fail(CodeMalformed, "signature must be %d bytes", ed25519.SignatureSize)
	}
	return &jws{
		kid:          h.Kid,
		jwk:          h.JWK,
		payloadB64:   parts[1],
		payload:      payload,
		signingInput: parts[0] + "." + parts[1],
		sig:          sig,
	}, nil
}

func (t *jws) verify(pub ed25519.PublicKey) error {
	if !canonicalS(t.sig) || !ed25519.Verify(pub, []byte(t.signingInput), t.sig) {
		return fail(CodeBadSignature, "signature does not verify")
	}
	return nil
}
