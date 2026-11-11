// Package vkeys derives the published test-vector keys and builds and checks
// the compact JWS used in vectors. Test use only.
package vkeys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/edkey"
)

// Note goes into every vector file.
const Note = "TEST ONLY. Every key in this file is derived from a published seed; never use these keys outside tests."

// Key derives the private key published as name.
func Key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("seawise test vector key: " + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

// Pub is the public half of Key(name).
func Pub(name string) ed25519.PublicKey { return Key(name).Public().(ed25519.PublicKey) }

// KID is the RFC 7638 thumbprint of Pub(name).
func KID(name string) string { return edkey.KeyID(Pub(name)) }

// Info describes one key in a vector file.
type Info struct {
	Name string `json:"name"`
	Seed string `json:"seed"`
	X    string `json:"x"`
	KID  string `json:"kid"`
}

// Infos lists the named keys.
func Infos(names ...string) []Info {
	out := make([]Info, 0, len(names))
	for _, n := range names {
		out = append(out, Info{Name: n, Seed: hex.EncodeToString(Key(n).Seed()), X: B64(Pub(n)), KID: KID(n)})
	}
	return out
}

// B64 is unpadded base64url.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// JSON marshals v and panics on error.
func JSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// SignRaw signs header and payload text as a compact JWS.
func SignRaw(priv ed25519.PrivateKey, header, payload string) string {
	in := B64([]byte(header)) + "." + B64([]byte(payload))
	return in + "." + B64(ed25519.Sign(priv, []byte(in)))
}

// SignJWS signs claims with a kid header.
func SignJWS(priv ed25519.PrivateKey, typ string, claims any) string {
	h := JSON(struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{typ, "EdDSA", edkey.KeyID(priv.Public().(ed25519.PublicKey))})
	return SignRaw(priv, string(h), string(JSON(claims)))
}

// VerifyJWS checks a compact JWS with typ and a kid header against keys and
// returns the payload and the name of the signing key. It stands in for
// the consumers' strict verifiers in vector tests.
func VerifyJWS(tok, typ string, keys map[string]ed25519.PublicKey) ([]byte, string, error) {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return nil, "", errors.New("malformed")
	}
	hb, err := base64.RawURLEncoding.Strict().DecodeString(p[0])
	if err != nil {
		return nil, "", errors.New("malformed")
	}
	var h struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &h) != nil || h.Alg != "EdDSA" || h.Typ != typ {
		return nil, "", errors.New("bad_header")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(p[2])
	if err != nil {
		return nil, "", errors.New("malformed")
	}
	for name, pub := range keys {
		if edkey.KeyID(pub) != h.Kid {
			continue
		}
		if !edkey.Verify(pub, []byte(p[0]+"."+p[1]), sig) {
			return nil, "", errors.New("bad_signature")
		}
		pl, err := base64.RawURLEncoding.Strict().DecodeString(p[1])
		if err != nil {
			return nil, "", errors.New("malformed")
		}
		return pl, name, nil
	}
	return nil, "", errors.New("unknown_key")
}

// Dir is the vector directory relative to a package directory.
const Dir = "../testdata/vectors"

// Sync writes want to the vector file when update is set and otherwise
// reports whether the committed file equals want.
func Sync(name string, want []byte, update bool) (bool, error) {
	path := filepath.Join(Dir, name)
	if update {
		return true, os.WriteFile(path, want, 0o644)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return string(got) == string(want), nil
}

// Load reads a committed vector file.
func Load(name string) ([]byte, error) { return os.ReadFile(filepath.Join(Dir, name)) }

// Pretty indents a vector file and ends it with a newline.
func Pretty(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// SignJWK signs claims with the public key in a jwk header, as DPoP does.
func SignJWK(priv ed25519.PrivateKey, typ string, claims any) string {
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	h := JSON(struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK jwk    `json:"jwk"`
	}{typ, "EdDSA", jwk{"OKP", "Ed25519", B64(priv.Public().(ed25519.PublicKey))}})
	return SignRaw(priv, string(h), string(JSON(claims)))
}

// VerifyJWK checks a compact JWS with a jwk header and returns the payload
// and the key.
func VerifyJWK(tok, typ string) ([]byte, ed25519.PublicKey, error) {
	p := strings.Split(tok, ".")
	if len(p) != 3 {
		return nil, nil, errors.New("malformed")
	}
	hb, err1 := base64.RawURLEncoding.Strict().DecodeString(p[0])
	pl, err2 := base64.RawURLEncoding.Strict().DecodeString(p[1])
	sig, err3 := base64.RawURLEncoding.Strict().DecodeString(p[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, nil, errors.New("malformed")
	}
	var h struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
		} `json:"jwk"`
	}
	if json.Unmarshal(hb, &h) != nil || h.Typ != typ || h.Alg != "EdDSA" || h.JWK.Kty != "OKP" || h.JWK.Crv != "Ed25519" {
		return nil, nil, errors.New("bad_header")
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(h.JWK.X)
	if err != nil || !edkey.Verify(pub, []byte(p[0]+"."+p[1]), sig) {
		return nil, nil, errors.New("bad_signature")
	}
	return pl, pub, nil
}
