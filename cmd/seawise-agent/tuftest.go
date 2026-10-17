//go:build seawise_tuftest

package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/updatecheck"
)

// Built only by the memory budget test: reads a test root, repository URL
// and CA from SEAWISE_TEST_TUF_DIR.
func init() {
	testUpdateConfig = func(cfg *updatecheck.Config) {
		dir := os.Getenv("SEAWISE_TEST_TUF_DIR")
		if dir == "" {
			return
		}
		root, _ := os.ReadFile(filepath.Join(dir, "root.json"))
		url, _ := os.ReadFile(filepath.Join(dir, "url"))
		ca, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca)
		cfg.Root, cfg.URL, cfg.AllowTestRoot = root, strings.TrimSpace(string(url)), true
		cfg.Transport = controlplane.NewTransport(os.Getenv, pool)
		cfg.FirstDelay = time.Millisecond
	}
}
