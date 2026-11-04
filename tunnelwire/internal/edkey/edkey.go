// Package edkey holds the Ed25519 key checks shared by the handshake code.
package edkey

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

var (
	ErrKeySize    = errors.New("public key must be 32 bytes")
	ErrNotOnCurve = errors.New("public key is not a canonical curve point")
	ErrSmallOrder = errors.New("public key has small order")
)

// KeyID returns the RFC 7638 JWK thumbprint of pub, base64url.
func KeyID(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	d := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// Check refuses a key that is not 32 bytes, not a canonical encoding of a
// curve point, or of small order. crypto/ed25519 accepts small-order keys,
// for which signatures can be forged.
func Check(b []byte) error {
	if len(b) != ed25519.PublicKeySize {
		return ErrKeySize
	}
	x, y, ok := decodePoint(b)
	if !ok {
		return ErrNotOnCurve
	}
	for range 3 {
		x, y = pointDouble(x, y)
	}
	if x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0 {
		return ErrSmallOrder
	}
	return nil
}

// Verify checks sig over msg with a key that passed Check. It refuses a
// non-canonical scalar.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize || Check(pub) != nil || !canonicalS(sig) {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

var (
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()
	sqrtM1    = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 2), fieldP)
	groupL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
)

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

func canonicalS(sig []byte) bool {
	le := make([]byte, 32)
	for i := range 32 {
		le[31-i] = sig[32+i]
	}
	return new(big.Int).SetBytes(le).Cmp(groupL) < 0
}
