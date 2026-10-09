package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
)

// JWK is the public key form used in tokens.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// PublicJWK returns the JWK of pub.
func PublicJWK(pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64Encode(pub)}
}

func thumbprintDigest(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64Encode(pub) + `"}`))
}

// KeyID returns the RFC 7638 JWK thumbprint of pub.
func KeyID(pub ed25519.PublicKey) string {
	d := thumbprintDigest(pub)
	return b64Encode(d[:])
}

// Fingerprint returns the display fingerprint of pub,
// SW-XXXX-XXXX-XXXX-XXXX: 64 bits of the key ID digest. It is for people to
// compare, never an identifier or an authentication factor.
func Fingerprint(pub ed25519.PublicKey) string {
	d := thumbprintDigest(pub)
	h := strings.ToUpper(hex.EncodeToString(d[:8]))
	return "SW-" + h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16]
}

// ParsePublicKey decodes a base64url public key and checks it.
func ParsePublicKey(x string) (ed25519.PublicKey, error) {
	b, err := b64Decode(x)
	if err != nil {
		return nil, fail(CodeMalformed, "public key is not base64url")
	}
	if err := CheckPublicKey(b); err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

func parseJWK(raw []byte) (ed25519.PublicKey, error) {
	keys, err := scanObject(raw)
	if err != nil {
		return nil, fail(CodeMalformed, "jwk: %v", err)
	}
	if keys["d"] {
		return nil, fail(CodeBadKey, "jwk holds a private key")
	}
	var j JWK
	if err := decodeObject(raw, &j, []string{"kty", "crv", "x"}); err != nil {
		return nil, err
	}
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fail(CodeBadKey, "jwk is not an Ed25519 key")
	}
	return ParsePublicKey(j.X)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()
	sqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 2), fieldP)
	// groupL is the order of the prime-order subgroup.
	groupL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
)

// CheckPublicKey refuses a key that is not 32 bytes, not a canonical
// encoding of a curve point, or of small order. crypto/ed25519 accepts
// small-order keys, for which signatures can be forged.
func CheckPublicKey(b []byte) error {
	if len(b) != ed25519.PublicKeySize {
		return fail(CodeBadKey, "public key must be %d bytes", ed25519.PublicKeySize)
	}
	x, y, ok := decodePoint(b)
	if !ok {
		return fail(CodeBadKey, "public key is not a canonical curve point")
	}
	for range 3 {
		x, y = pointDouble(x, y)
	}
	if x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0 {
		return fail(CodeBadKey, "public key has small order")
	}
	return nil
}

// decodePoint follows RFC 8032 section 5.1.3 and refuses y >= p.
func decodePoint(b []byte) (x, y *big.Int, ok bool) {
	le := make([]byte, 32)
	for i := range 32 {
		le[31-i] = b[i]
	}
	sign := le[0] >> 7
	le[0] &= 0x7f
	y = new(big.Int).SetBytes(le)
	p := fieldP
	if y.Cmp(p) >= 0 {
		return nil, nil, false
	}
	yy := new(big.Int).Mul(y, y)
	yy.Mod(yy, p)
	u := new(big.Int).Sub(yy, big.NewInt(1))
	u.Mod(u, p)
	v := new(big.Int).Mul(curveD, yy)
	v.Add(v, big.NewInt(1))
	v.Mod(v, p)

	// x = u v^3 (u v^7)^((p-5)/8)
	v3 := new(big.Int).Exp(v, big.NewInt(3), p)
	v7 := new(big.Int).Exp(v, big.NewInt(7), p)
	e := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(5)), 3)
	t := new(big.Int).Mul(u, v7)
	t.Exp(t.Mod(t, p), e, p)
	x = new(big.Int).Mul(u, v3)
	x.Mul(x, t)
	x.Mod(x, p)

	vxx := new(big.Int).Mul(x, x)
	vxx.Mul(vxx, v)
	vxx.Mod(vxx, p)
	negU := new(big.Int).Sub(p, u)
	negU.Mod(negU, p)
	switch {
	case vxx.Cmp(u) == 0:
	case vxx.Cmp(negU) == 0:
		x.Mul(x, sqrtM1)
		x.Mod(x, p)
	default:
		return nil, nil, false
	}
	if x.Sign() == 0 && sign == 1 {
		return nil, nil, false
	}
	if uint(x.Bit(0)) != uint(sign) {
		x.Sub(p, x)
	}
	return x, y, true
}

// pointDouble doubles an affine point on -x^2 + y^2 = 1 + d x^2 y^2. The
// curve is complete, so the denominators are never zero.
func pointDouble(x, y *big.Int) (*big.Int, *big.Int) {
	p := fieldP
	xx := new(big.Int).Mul(x, x)
	yy := new(big.Int).Mul(y, y)
	xy2 := new(big.Int).Mul(x, y)
	xy2.Lsh(xy2, 1)
	d1 := new(big.Int).Sub(yy, xx)
	d1.Mod(d1, p)
	n2 := new(big.Int).Add(yy, xx)
	d2 := new(big.Int).Sub(big.NewInt(2), yy)
	d2.Add(d2, xx)
	d2.Mod(d2, p)
	x3 := xy2.Mul(xy2, new(big.Int).ModInverse(d1, p))
	x3.Mod(x3, p)
	y3 := n2.Mul(n2, new(big.Int).ModInverse(d2, p))
	y3.Mod(y3, p)
	return x3, y3
}

// canonicalS reports whether the scalar half of sig is below the group order.
func canonicalS(sig []byte) bool {
	le := make([]byte, 32)
	for i := range 32 {
		le[31-i] = sig[32+i]
	}
	return new(big.Int).SetBytes(le).Cmp(groupL) < 0
}
