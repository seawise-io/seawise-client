package edkey

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestKeyIDMatchesRFC7638(t *testing.T) {
	// RFC 8037 appendix A.3 thumbprint.
	pub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if got := KeyID(pub); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("KeyID = %s", got)
	}
}

func TestCheck(t *testing.T) {
	seed := sha256.Sum256([]byte("edkey test"))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	if err := Check(pub); err != nil {
		t.Fatal(err)
	}
	if Check(pub[:31]) != ErrKeySize {
		t.Fatal("short key accepted")
	}
	identity := make([]byte, 32)
	identity[0] = 1
	if Check(identity) != ErrSmallOrder {
		t.Fatal("identity point accepted")
	}
	// y = p, a non-canonical encoding of y = 0.
	nonCanon, _ := hex.DecodeString("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if Check(nonCanon) != ErrNotOnCurve {
		t.Fatal("non-canonical point accepted")
	}
	// order-4 point (0, -1) with the sign bit set on x = 0.
	negZero, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000080")
	if Check(negZero) != ErrNotOnCurve {
		t.Fatal("negative zero accepted")
	}
	// y = 2 has no x on the curve.
	notOnCurve := make([]byte, 32)
	notOnCurve[0] = 2
	if Check(notOnCurve) != ErrNotOnCurve {
		t.Fatal("off-curve point accepted")
	}
	// order-8 point.
	small, _ := hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	if Check(small) != ErrSmallOrder {
		t.Fatal("order-8 point accepted")
	}
}

func TestVerify(t *testing.T) {
	seed := sha256.Sum256([]byte("edkey test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, []byte("m"))
	if !Verify(pub, []byte("m"), sig) {
		t.Fatal("valid signature refused")
	}
	if Verify(pub, []byte("n"), sig) || Verify(pub, []byte("m"), sig[:63]) {
		t.Fatal("bad signature accepted")
	}
	high := append([]byte(nil), sig...)
	high[63] |= 0xf0
	if Verify(pub, []byte("m"), high) {
		t.Fatal("non-canonical scalar accepted")
	}
	identity := make([]byte, 32)
	identity[0] = 1
	if Verify(identity, []byte("m"), sig) {
		t.Fatal("small-order key accepted")
	}
}
