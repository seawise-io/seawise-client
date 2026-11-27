//go:build seawise_tuftest

package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/seawise/client/internal/keyset"
)

func TestTestBuildPinsKeySetRootsFromTheTestDir(t *testing.T) {
	pub := testTUFDir(t)
	var ks keyset.Config
	testKeySetConfig(&ks)
	if len(ks.Roots) != 1 || !ks.Roots[0].Equal(pub) || !ks.AllowTestRoots {
		t.Fatalf("roots %v, allow test roots %v", ks.Roots, ks.AllowTestRoots)
	}
	if err := os.Remove(filepath.Join(os.Getenv("SEAWISE_TEST_TUF_DIR"), "keyset-roots.json")); err != nil {
		t.Fatal(err)
	}
	ks = keyset.Config{}
	testKeySetConfig(&ks)
	if ks.Roots != nil {
		t.Fatal("roots without keyset-roots.json or keyset-root")
	}
	// The test suites' single key, when keyset-roots.json is absent.
	if err := os.WriteFile(filepath.Join(os.Getenv("SEAWISE_TEST_TUF_DIR"), "keyset-root"), []byte(base64.RawURLEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ks = keyset.Config{}
	testKeySetConfig(&ks)
	if len(ks.Roots) != 1 || !ks.Roots[0].Equal(pub) || !ks.AllowTestRoots {
		t.Fatalf("keyset-root: roots %v, allow test roots %v", ks.Roots, ks.AllowTestRoots)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("SEAWISE_TEST_TUF_DIR"), "keyset-roots.json"), []byte(`{"roots":["nope"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a malformed keyset-roots.json was ignored")
		}
	}()
	testKeySetConfig(&keyset.Config{})
}
