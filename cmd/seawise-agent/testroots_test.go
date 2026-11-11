package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// testTUFDir writes a SEAWISE_TEST_TUF_DIR with a key-set root, a TUF root,
// a URL and a CA, and returns the key-set root.
func testTUFDir(t *testing.T) ed25519.PublicKey {
	t.Helper()
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"keyset-roots.json": `{"roots":["` + base64.RawURLEncoding.EncodeToString(pub) + `"]}`,
		"root.json":         `{"signed":{}}`,
		"url":               "https://tuf.example.test",
		"ca.pem":            "",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SEAWISE_TEST_TUF_DIR", dir)
	return pub
}
