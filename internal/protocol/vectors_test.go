package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var vectorDir = filepath.Join("..", "..", "testdata", "vectors")

func marshalVectors(f vecFile) []byte {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// TestVectorsUpToDate regenerates the vectors and compares them with the
// committed files. Run with UPDATE_VECTORS=1 to rewrite them.
func TestVectorsUpToDate(t *testing.T) {
	update := os.Getenv("UPDATE_VECTORS") == "1"
	gen := generateVectors()
	for name, f := range gen {
		want := marshalVectors(f)
		path := filepath.Join(vectorDir, name)
		if update {
			if err := os.MkdirAll(vectorDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with UPDATE_VECTORS=1)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the generator (run with UPDATE_VECTORS=1 and review the diff)", name)
		}
	}
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, ok := gen[e.Name()]; !ok {
			t.Errorf("unexpected file %s in %s", e.Name(), vectorDir)
		}
	}
}

func TestVectorsDeterministic(t *testing.T) {
	a, b := generateVectors(), generateVectors()
	for name := range a {
		if !bytes.Equal(marshalVectors(a[name]), marshalVectors(b[name])) {
			t.Errorf("%s is not deterministic", name)
		}
	}
}

func TestSmallOrderSearchComplete(t *testing.T) {
	if n := len(smallOrderEncodings()); n != 8 {
		t.Fatalf("found %d small-order points, want 8", n)
	}
}

func loadVectors(t *testing.T, name string) vecFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var f vecFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if f.Note != vectorNote || len(f.Cases) == 0 {
		t.Fatalf("%s: missing note or cases", name)
	}
	return f
}

func ctxOf[T any](t *testing.T, c vecCase) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(c.Context, &v); err != nil {
		t.Fatalf("%s: context: %v", c.Name, err)
	}
	return v
}

func checkCase(t *testing.T, c vecCase, result any, err error) {
	t.Helper()
	if c.Expect == "ok" {
		if err != nil {
			t.Errorf("%s: want ok, got %v", c.Name, err)
			return
		}
		var got, want any
		_ = json.Unmarshal(mustJSON(result), &got)
		_ = json.Unmarshal(c.Result, &want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: result %s, want %s", c.Name, mustJSON(result), c.Result)
		}
		return
	}
	if code := CodeOf(err); string(code) != c.Expect {
		t.Errorf("%s: want %s, got %v", c.Name, c.Expect, err)
	}
}

func registryLookup(t *testing.T, reg []registryJSON) func(string) (RegistryEntry, bool) {
	m := map[string]RegistryEntry{}
	for _, r := range reg {
		pub, err := ParsePublicKey(r.X)
		if err != nil {
			t.Fatal(err)
		}
		m[KeyID(pub)] = RegistryEntry{ServerID: r.ServerID, PublicKey: pub, Status: r.Status, ValidFrom: r.ValidFrom}
	}
	return func(kid string) (RegistryEntry, bool) { e, ok := m[kid]; return e, ok }
}

func vectorKeySet(t *testing.T, token string, roots []string) *KeySet {
	t.Helper()
	ks, err := VerifyKeySet(token, parseRoots(t, roots), 0, [32]byte{})
	if err != nil {
		t.Fatalf("context key set: %v", err)
	}
	return ks
}

func parseRoots(t *testing.T, roots []string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, r := range roots {
		pub, err := ParsePublicKey(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pub)
	}
	return out
}

func TestVectorsVerify(t *testing.T) {
	t.Run("keys", func(t *testing.T) {
		for _, c := range loadVectors(t, "keys.json").Cases {
			pub, err := ParsePublicKey(c.Input)
			var res any
			if err == nil {
				res = keyResult{KID: KeyID(pub), Fingerprint: Fingerprint(pub)}
			}
			checkCase(t, c, res, err)
		}
	})
	t.Run("dpop", func(t *testing.T) {
		for _, c := range loadVectors(t, "dpop.json").Cases {
			ctx := ctxOf[dpopContext](t, c)
			r, err := VerifyDPoP(c.Input, DPoPRequest{Method: ctx.Method, URL: ctx.URL, Body: []byte(ctx.Body)},
				func(n string) bool { return slices.Contains(ctx.ValidNonces, n) },
				func(kid, jti string) bool { return !slices.Contains(ctx.Seen, seenJTI{KID: kid, JTI: jti}) })
			var res any
			if err == nil {
				res = dpopResult{KID: r.KeyID, JTI: r.Claims.JTI}
			}
			checkCase(t, c, res, err)
		}
	})
	t.Run("frp_token", func(t *testing.T) {
		for _, c := range loadVectors(t, "frp_token.json").Cases {
			ctx := ctxOf[frpContext](t, c)
			conflict := func(server, run string) bool {
				for _, l := range ctx.LiveRuns {
					if l.ServerID == server && l.RunID != run {
						return true
					}
				}
				return false
			}
			r, err := VerifyFRPToken(c.Input, ctx.LoginServerID, registryLookup(t, ctx.Registry), ctx.Now, conflict)
			checkCase(t, c, r, err)
		}
	})
	t.Run("rotation", func(t *testing.T) {
		for _, c := range loadVectors(t, "rotation.json").Cases {
			ctx := ctxOf[rotationContext](t, c)
			rot, err := ParseRotation([]byte(c.Input))
			var res any
			if err == nil {
				var r *RotationResult
				r, err = VerifyRotation(rot, RotationCheck{
					ServerID:       ctx.ServerID,
					Lookup:         registryLookup(t, ctx.Registry),
					PreviousKeyIDs: ctx.PreviousKIDs,
					Applied:        func(kid string) (Rotation, bool) { r, ok := ctx.Applied[kid]; return r, ok },
				})
				if err == nil {
					res = rotationResult{OldKID: r.OldKeyID, NewKID: r.NewKeyID, AlreadyApplied: r.AlreadyApplied}
				}
			}
			checkCase(t, c, res, err)
		}
	})
	t.Run("keyset", func(t *testing.T) {
		for _, c := range loadVectors(t, "keyset.json").Cases {
			ctx := ctxOf[keysetContext](t, c)
			var last [32]byte
			if ctx.LastDigest != "" {
				d, err := b64Decode(ctx.LastDigest)
				if err != nil || len(d) != 32 {
					t.Fatalf("%s: bad last_digest", c.Name)
				}
				copy(last[:], d)
			}
			ks, err := VerifyKeySet(c.Input, parseRoots(t, ctx.Roots), ctx.LastVersion, last)
			var res any
			if err == nil {
				kids := []string{}
				for _, e := range ks.Keys {
					kids = append(kids, e.KID)
				}
				res = keysetResult{Version: ks.Version, KIDs: kids, Digest: b64Encode(ks.Digest[:])}
			}
			checkCase(t, c, res, err)
		}
	})
	t.Run("instruction", func(t *testing.T) {
		for _, c := range loadVectors(t, "instruction.json").Cases {
			ctx := ctxOf[instrContext](t, c)
			ks := vectorKeySet(t, ctx.KeySet, ctx.Roots)
			in, err := VerifyInstruction(c.Input, ks, ctx.ServerID, ctx.Now, func(id string) bool { return slices.Contains(ctx.Executed, id) })
			checkCase(t, c, in, err)
		}
	})
	t.Run("signed_time", func(t *testing.T) {
		for _, c := range loadVectors(t, "signed_time.json").Cases {
			ctx := ctxOf[timeContext](t, c)
			ks := vectorKeySet(t, ctx.KeySet, ctx.Roots)
			st, err := VerifySignedTime(c.Input, ks, ctx.ServerID, ctx.Nonce)
			checkCase(t, c, st, err)
		}
	})
}

// TestVectorsCoverEveryCode keeps the shared suite honest: every error code
// a verifier can return appears in at least one vector.
func TestVectorsCoverEveryCode(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range generateVectors() {
		for _, c := range f.Cases {
			seen[c.Expect] = true
		}
	}
	for _, code := range []Code{CodeTooLarge, CodeMalformed, CodeBadAlg, CodeBadTyp, CodeBadKey, CodeBadSignature, CodeUnknownKey,
		CodeKeyRevoked, CodeWrongKeyRole, CodeWrongServer, CodeExpired, CodeNotYetValid, CodeBeforeKeyValid, CodeReplayed,
		CodeWrongHTM, CodeWrongHTU, CodeBodyMismatch, CodeBadNonce, CodeNonceMismatch, CodeRollback, CodeRunConflict} {
		if !seen[string(code)] {
			t.Errorf("no vector expects %s", code)
		}
	}
}

func TestVectorWireCodes(t *testing.T) {
	for name, f := range generateVectors() {
		for _, c := range f.Cases {
			switch {
			case c.Expect == "ok" && c.Wire != "":
				t.Errorf("%s/%s: wire code on a valid case", name, c.Name)
			case (c.Expect == "unknown_key" || c.Expect == "bad_signature") && c.Wire != "invalid_proof":
				t.Errorf("%s/%s: wire %q", name, c.Name, c.Wire)
			}
		}
	}
}

// TestVectorKeyIDsListed keeps the exported deny list equal to the keys
// the vectors publish.
func TestVectorKeyIDsListed(t *testing.T) {
	var want []string
	for _, n := range vecKeyNames {
		want = append(want, vecKID(n))
	}
	slices.Sort(want)
	got := slices.Sorted(slices.Values(TestVectorKeyIDs))
	if !slices.Equal(got, want) {
		t.Fatalf("TestVectorKeyIDs is out of date; want:\n%s", strings.Join(want, "\n"))
	}
	for name, f := range generateVectors() {
		for _, k := range f.Keys {
			if !IsTestVectorKey(k.KID) {
				t.Errorf("%s: key %s not in TestVectorKeyIDs", name, k.Name)
			}
		}
	}
}
