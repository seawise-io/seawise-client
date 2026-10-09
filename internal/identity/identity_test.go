package identity

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/store"
)

const testServer = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"

var fixedNow = func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }

func stateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "v2")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openFile(t *testing.T, dir string) *FileKeystore {
	t.Helper()
	ks, err := OpenFile(dir, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ks.Close() })
	return ks
}

func create(t *testing.T, ks Keystore) *Key {
	t.Helper()
	k, err := ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// secretForms returns every encoding of the private key a leak could use.
func secretForms(t *testing.T, k *Key) []string {
	t.Helper()
	seed, err := k.seed()
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var out []string
	for _, b := range [][]byte{seed, priv} {
		out = append(out,
			hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
			base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
			base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
			string(b), fmt.Sprint([]byte(b)))
	}
	return out
}

func assertNoSecret(t *testing.T, what, s string, secrets []string) {
	t.Helper()
	for _, sec := range secrets {
		if strings.Contains(s, sec) {
			t.Fatalf("%s leaks private key material: %q", what, s)
		}
	}
}

func TestKeyNeverFormatsPrivate(t *testing.T) {
	ks := openFile(t, stateDir(t))
	k := create(t, ks)
	secrets := secretForms(t, k)
	holder := struct {
		Key  *Key
		Val  Key
		List []*Key
	}{k, *k, []*Key{k}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		for _, v := range []any{k, *k, holder} {
			assertNoSecret(t, verb, fmt.Sprintf(verb, v), secrets)
		}
	}
	for _, v := range []any{k, *k, holder} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, "json", string(b), secrets)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("key", "key", k, "value", *k, "holder", holder)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("key", "key", k)
	assertNoSecret(t, "slog", buf.String(), secrets)
	if !strings.Contains(buf.String(), k.Fingerprint()) {
		t.Fatal("logs should carry the fingerprint")
	}
	err := fmt.Errorf("wrapped: %v", k)
	assertNoSecret(t, "error", err.Error(), secrets)
}

func TestInfoIsPublicOnly(t *testing.T) {
	ks := openFile(t, stateDir(t))
	k := create(t, ks)
	info := k.Info()
	if info.KeyID != protocol.KeyID(k.PublicKey()) || info.Fingerprint != protocol.Fingerprint(k.PublicKey()) {
		t.Fatal("info does not match the key")
	}
	pub, err := protocol.ParsePublicKey(info.PublicKey)
	if err != nil || !pub.Equal(k.PublicKey()) {
		t.Fatal("info public key does not round trip")
	}
	b, _ := json.Marshal(k)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if len(got) != 3 {
		t.Fatalf("JSON has members %v, want public_key, key_id, fingerprint", got)
	}
}

// No exported method or field may hand out private material.
func TestNoPrivateAccessor(t *testing.T) {
	privT := reflect.TypeOf(ed25519.PrivateKey(nil))
	for _, typ := range []reflect.Type{reflect.TypeOf(Key{}), reflect.TypeOf(&Key{}), reflect.TypeOf(&FileKeystore{})} {
		for i := range typ.NumMethod() {
			m := typ.Method(i)
			for j := range m.Type.NumOut() {
				if out := m.Type.Out(j); out == privT || strings.Contains(strings.ToLower(m.Name), "seed") || strings.Contains(strings.ToLower(m.Name), "private") {
					t.Errorf("%s.%s exposes private material (%v)", typ, m.Name, out)
				}
			}
		}
		if typ.Kind() == reflect.Struct {
			for i := range typ.NumField() {
				if typ.Field(i).IsExported() {
					t.Errorf("%s has exported field %s", typ, typ.Field(i).Name)
				}
			}
		}
	}
}

func TestSign(t *testing.T) {
	ks := openFile(t, stateDir(t))
	k := create(t, ks)
	msg := []byte("message")
	sig, err := k.Sign(nil, msg, crypto.Hash(0))
	if err != nil || !ed25519.Verify(k.PublicKey(), msg, sig) {
		t.Fatalf("sign: %v", err)
	}
	if sig2, _ := k.Sign(nil, msg, &ed25519.Options{}); !bytes.Equal(sig, sig2) {
		t.Fatal("plain options should sign the same")
	}
	for _, opts := range []crypto.SignerOpts{nil, crypto.SHA256, &ed25519.Options{Hash: crypto.SHA512}, &ed25519.Options{Context: "x"}} {
		if _, err := k.Sign(nil, msg, opts); !errors.Is(err, errHashOpts) {
			t.Errorf("opts %v: %v, want refusal", opts, err)
		}
	}
	tok, err := protocol.NewFRPToken(k, testServer, "cnVuLWlkLTAwMDAwMDAwMDE", 100)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(kid string) (protocol.RegistryEntry, bool) {
		return protocol.RegistryEntry{ServerID: testServer, PublicKey: k.PublicKey(), Status: protocol.StatusActive}, kid == k.KeyID()
	}
	if _, err := protocol.VerifyFRPToken(tok, testServer, lookup, 100); err != nil {
		t.Fatalf("token from keystore key: %v", err)
	}
}

func TestDestroyZeroes(t *testing.T) {
	ks := openFile(t, stateDir(t))
	k := create(t, ks)
	priv := k.d.priv
	if err := ks.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv, make([]byte, len(priv))) {
		t.Fatal("private key not zeroed on close")
	}
	if _, err := k.Sign(nil, []byte("m"), crypto.Hash(0)); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("sign after close: %v", err)
	}
	if _, err := ks.Current(); !errors.Is(err, ErrClosed) {
		t.Fatalf("current after close: %v", err)
	}
}

func TestCreateLoad(t *testing.T) {
	dir := stateDir(t)
	ks := openFile(t, dir)
	if _, err := ks.Current(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty store: %v", err)
	}
	k := create(t, ks)
	if !k.CreatedAt().Equal(fixedNow()) {
		t.Fatalf("created_at %v", k.CreatedAt())
	}
	if _, err := ks.Create(); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second create: %v", err)
	}
	ks.Close()
	again := openFile(t, dir)
	cur, err := again.Current()
	if err != nil || cur.KeyID() != k.KeyID() || !cur.CreatedAt().Equal(k.CreatedAt()) {
		t.Fatalf("reload: %v", err)
	}
	if _, err := again.Create(); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("create after reload: %v", err)
	}
}

func TestGeneratedKeysDiffer(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		k, err := generate(fixedNow())
		if err != nil {
			t.Fatal(err)
		}
		if seen[k.KeyID()] {
			t.Fatal("duplicate key")
		}
		seen[k.KeyID()] = true
	}
}

func TestFileMode(t *testing.T) {
	dir := stateDir(t)
	create(t, openFile(t, dir))
	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func skipNonUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership checks are unix only")
	}
}

func TestFileRefusesLooseMode(t *testing.T) {
	skipNonUnix(t)
	dir := stateDir(t)
	create(t, openFile(t, dir))
	if err := os.Chmod(filepath.Join(dir, KeyFile), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(dir, fixedNow); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("group-readable key file: %v", err)
	}
}

func TestFileRefusesSymlink(t *testing.T) {
	skipNonUnix(t)
	dir := stateDir(t)
	other := stateDir(t)
	create(t, openFile(t, other))
	if err := os.Symlink(filepath.Join(other, KeyFile), filepath.Join(dir, KeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(dir, fixedNow); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("symlinked key file: %v", err)
	}
}

func TestDirChecks(t *testing.T) {
	skipNonUnix(t)
	dir := stateDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(dir, fixedNow); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("world-readable dir: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(stateDir(t), link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(link, fixedNow); !errors.Is(err, store.ErrUnsafePath) {
		t.Fatalf("symlinked dir: %v", err)
	}
}

func rewrite(t *testing.T, dir string, fn func(doc map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, KeyFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	b, _ = json.Marshal(doc)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFileCorrupt(t *testing.T) {
	other, _ := generate(fixedNow())
	for name, tc := range map[string]struct {
		mut  func(map[string]any)
		want error
	}{
		"swapped public key": {func(d map[string]any) {
			d["current"].(map[string]any)["public_key"] = other.Info().PublicKey
		}, ErrCorrupt},
		"short seed":     {func(d map[string]any) { d["current"].(map[string]any)["seed"] = "AAAA" }, ErrCorrupt},
		"unknown member": {func(d map[string]any) { d["note"] = "x" }, ErrCorrupt},
		"no current":     {func(d map[string]any) { delete(d, "current") }, ErrCorrupt},
		"newer schema":   {func(d map[string]any) { d["schema"] = 2 }, store.ErrNewerSchema},
		"pending equals current": {func(d map[string]any) {
			d["pending"] = d["current"]
		}, ErrCorrupt},
	} {
		t.Run(name, func(t *testing.T) {
			dir := stateDir(t)
			create(t, openFile(t, dir))
			rewrite(t, dir, tc.mut)
			if _, err := OpenFile(dir, fixedNow); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("trailing data", func(t *testing.T) {
		dir := stateDir(t)
		create(t, openFile(t, dir))
		f, _ := os.OpenFile(filepath.Join(dir, KeyFile), os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("{}")
		f.Close()
		if _, err := OpenFile(dir, fixedNow); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRotation(t *testing.T) {
	dir := stateDir(t)
	ks := openFile(t, dir)
	if _, err := ks.BeginRotation(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("rotation without key: %v", err)
	}
	old := create(t, ks)
	rot, err := Rotate(ks, testServer)
	if err != nil {
		t.Fatal(err)
	}
	pend, err := ks.Pending()
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(kid string) (protocol.RegistryEntry, bool) {
		return protocol.RegistryEntry{ServerID: testServer, PublicKey: old.PublicKey(), Status: protocol.StatusActive}, kid == old.KeyID()
	}
	res, err := protocol.VerifyRotation(rot, testServer, lookup)
	if err != nil {
		t.Fatalf("rotation does not verify: %v", err)
	}
	if res.NewKeyID != pend.KeyID() || res.IAT != fixedNow().Unix() {
		t.Fatal("rotation names the wrong key or time")
	}

	// A crash before the server answers: the pending key survives and a
	// retry produces the identical statement.
	ks.Close()
	ks = openFile(t, dir)
	old, _ = ks.Current()
	retry, err := Rotate(ks, testServer)
	if err != nil {
		t.Fatal(err)
	}
	if retry != rot {
		t.Fatal("retried rotation differs")
	}

	if err := ks.CommitRotation(); err != nil {
		t.Fatal(err)
	}
	cur, _ := ks.Current()
	if cur.KeyID() != pend.KeyID() {
		t.Fatal("commit did not promote the pending key")
	}
	if _, err := ks.Pending(); !errors.Is(err, ErrNoKey) {
		t.Fatal("pending key left after commit")
	}
	if _, err := old.Sign(nil, []byte("m"), crypto.Hash(0)); !errors.Is(err, ErrDestroyed) {
		t.Fatal("old key still signs after commit")
	}
	ks.Close()
	reloaded, _ := openFile(t, dir).Current()
	if reloaded.KeyID() != pend.KeyID() {
		t.Fatal("commit not persisted")
	}
}

func TestAbortRotation(t *testing.T) {
	dir := stateDir(t)
	ks := openFile(t, dir)
	old := create(t, ks)
	if err := ks.AbortRotation(); err != nil {
		t.Fatalf("abort with nothing pending: %v", err)
	}
	pend, _ := ks.BeginRotation()
	if err := ks.AbortRotation(); err != nil {
		t.Fatal(err)
	}
	if _, err := pend.Sign(nil, []byte("m"), crypto.Hash(0)); !errors.Is(err, ErrDestroyed) {
		t.Fatal("aborted key still signs")
	}
	if err := ks.CommitRotation(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("commit without pending: %v", err)
	}
	ks.Close()
	cur, _ := openFile(t, dir).Current()
	if cur.KeyID() != old.KeyID() {
		t.Fatal("abort changed the current key")
	}
}

func TestConcurrentUse(t *testing.T) {
	ks := openFile(t, stateDir(t))
	create(t, ks)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				k, err := ks.Current()
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = k.Sign(nil, []byte("m"), crypto.Hash(0))
				if i == 0 {
					_, _ = ks.BeginRotation()
					_ = ks.AbortRotation()
				}
			}
		}()
	}
	wg.Wait()
}

func TestBackends(t *testing.T) {
	for _, b := range []string{BackendKeychain, BackendDPAPI, BackendTPM} {
		if _, err := Open(b, stateDir(t), fixedNow); !errors.Is(err, ErrUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s: %v, want unsupported", b, err)
		}
	}
	if _, err := Open("plaintext", stateDir(t), fixedNow); err == nil || errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown backend: %v", err)
	}
	ks, err := Open(BackendFile, stateDir(t), fixedNow)
	if err != nil || ks.Backend() != BackendFile {
		t.Fatalf("file backend: %v", err)
	}
	ks.Close()
}
