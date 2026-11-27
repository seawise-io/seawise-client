//go:build !seawise_tuftest

package main

import (
	"testing"

	"github.com/seawise/client/internal/keyset"
	"github.com/seawise/client/internal/updatecheck"
)

// A release build ignores SEAWISE_TEST_TUF_DIR: no test key-set root, TUF
// root, repository or CA can be pinned from the environment.
func TestReleaseBuildIgnoresTestRoots(t *testing.T) {
	testTUFDir(t)
	var ks keyset.Config
	testKeySetConfig(&ks)
	if ks.Roots != nil || ks.AllowTestRoots {
		t.Fatal("key-set roots taken from SEAWISE_TEST_TUF_DIR")
	}
	var uc updatecheck.Config
	testUpdateConfig(&uc)
	if uc.Root != nil || uc.URL != "" || uc.AllowTestRoot || uc.Transport != nil || uc.FirstDelay != 0 {
		t.Fatal("update check configured from SEAWISE_TEST_TUF_DIR")
	}
}
