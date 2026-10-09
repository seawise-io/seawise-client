package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// seedFromVectors adds every case input of a committed vector file.
func seedFromVectors(f *testing.F, name string) {
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		f.Fatal(err)
	}
	var v vecFile
	if err := json.Unmarshal(b, &v); err != nil {
		f.Fatal(err)
	}
	for _, c := range v.Cases {
		f.Add(c.Input)
	}
}

// mustBeCoded fails unless err is nil or a protocol error with a code: no
// verifier may fail in a way the vectors cannot express.
func mustBeCoded(t *testing.T, err error) {
	if err != nil && CodeOf(err) == "" {
		t.Fatalf("uncoded error: %v", err)
	}
}

func FuzzDPoP(f *testing.F) {
	seedFromVectors(f, "dpop.json")
	f.Fuzz(func(t *testing.T, proof string) {
		req := DPoPRequest{Method: "POST", URL: vecURL, Body: []byte(vecBody)}
		r, err := VerifyDPoP(proof, req, func(string) bool { return true }, func(string, string) bool { return true })
		mustBeCoded(t, err)
		if err == nil {
			if !ed25519.Verify(r.PublicKey, []byte(proof[:len(proof)-87]), mustB64(t, proof[len(proof)-86:])) {
				t.Fatal("accepted a proof whose signature does not verify")
			}
			if CheckPublicKey(r.PublicKey) != nil || r.Claims.HTM != "POST" || !ValidID(r.Claims.JTI) {
				t.Fatal("accepted invalid claims")
			}
		}
	})
}

func mustB64(t *testing.T, s string) []byte {
	b, err := b64Decode(s)
	if err != nil {
		t.Fatalf("accepted token has a bad signature segment: %v", err)
	}
	return b
}

func FuzzFRPToken(f *testing.F) {
	seedFromVectors(f, "frp_token.json")
	f.Fuzz(func(t *testing.T, tok string) {
		lookup := registryLookup(t, vecRegistry())
		c, err := VerifyFRPToken(tok, vecServer1, lookup, vecNow)
		mustBeCoded(t, err)
		if err == nil && (c.ServerID != vecServer1 || c.KeyID != vecKID("device-a")) {
			t.Fatalf("accepted a token for %s/%s", c.ServerID, c.KeyID)
		}
	})
}

func FuzzKeySet(f *testing.F) {
	seedFromVectors(f, "keyset.json")
	roots := []ed25519.PublicKey{vecPub("root-primary"), vecPub("root-backup")}
	f.Fuzz(func(t *testing.T, tok string) {
		ks, err := VerifyKeySet(tok, roots, 0, [32]byte{})
		mustBeCoded(t, err)
		if err == nil {
			for _, e := range ks.Keys {
				pub, err := ks.Lookup(e.KID, e.Role)
				if e.Status == StatusRevoked {
					if CodeOf(err) != CodeKeyRevoked {
						t.Fatal("revoked key usable")
					}
					continue
				}
				if err != nil || KeyID(pub) != e.KID || CheckPublicKey(pub) != nil {
					t.Fatal("inconsistent key set entry")
				}
			}
		}
	})
}

func FuzzInstruction(f *testing.F) {
	seedFromVectors(f, "instruction.json")
	ks, err := VerifyKeySet(vecKeySet(5), []ed25519.PublicKey{vecPub("root-primary")}, 0, [32]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		in, err := VerifyInstruction(tok, ks, vecServer1, vecNow, func(string) bool { return false })
		mustBeCoded(t, err)
		if err == nil {
			if in.ServerID != vecServer1 || in.check() != nil || in.EXP+leewaySec < vecNow {
				t.Fatal("accepted an invalid instruction")
			}
		}
	})
}

func FuzzSignedTime(f *testing.F) {
	seedFromVectors(f, "signed_time.json")
	ks, err := VerifyKeySet(vecKeySet(5), []ed25519.PublicKey{vecPub("root-primary")}, 0, [32]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		st, err := VerifySignedTime(tok, ks, vecServer1, vecTimeN)
		mustBeCoded(t, err)
		if err == nil && (st.Nonce != vecTimeN || st.ServerID != vecServer1) {
			t.Fatal("accepted time for another request")
		}
	})
}

func FuzzRotation(f *testing.F) {
	seedFromVectors(f, "rotation.json")
	f.Fuzz(func(t *testing.T, in string) {
		r, err := ParseRotation([]byte(in))
		mustBeCoded(t, err)
		if err != nil {
			return
		}
		res, err := VerifyRotation(r, vecServer1, registryLookup(t, vecRegistry()))
		mustBeCoded(t, err)
		if err == nil && (res.OldKeyID != vecKID("device-a") || CheckPublicKey(res.NewPublic) != nil) {
			t.Fatal("accepted an invalid rotation")
		}
	})
}

func FuzzPublicKey(f *testing.F) {
	seedFromVectors(f, "keys.json")
	f.Fuzz(func(t *testing.T, x string) {
		pub, err := ParsePublicKey(x)
		mustBeCoded(t, err)
		if err == nil && (len(pub) != 32 || b64Encode(pub) != x) {
			t.Fatal("accepted a non-canonical encoding")
		}
	})
}
