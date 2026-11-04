//go:build seawise_tuftest

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seawise/client/internal/appsync"
	"github.com/seawise/client/internal/controlplane"
	"github.com/seawise/client/internal/keyset"
	"github.com/seawise/client/internal/transport"
	"github.com/seawise/client/internal/updatecheck"
)

// Built only by the budget tests, the network fault suite and the local test
// stack; never by a release. Files in SEAWISE_TEST_TUF_DIR: root.json, url
// and ca.pem for the update check; keyset-roots.json ({"roots":[...]}, the
// local stack) or keyset-root (one base64url Ed25519 key, the test suites)
// for the key set. SEAWISE_TEST_EDGE_ADDR sends tunnel dials to that address;
// SEAWISE_TEST_LIST_EVERY shortens the app list period.
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
		cfg.Transport = controlplane.NewTransportAt(os.Getenv, pool, cfg.Now)
		cfg.FirstDelay = time.Millisecond
	}
	testKeySetConfig = func(cfg *keyset.Config) {
		dir := os.Getenv("SEAWISE_TEST_TUF_DIR")
		if dir == "" {
			return
		}
		if roots := testRoots(dir); roots != nil {
			cfg.Roots, cfg.AllowTestRoots = roots, true
		}
	}
	if addr := os.Getenv("SEAWISE_TEST_EDGE_ADDR"); addr != "" {
		testTransportConfig = func(cfg *transport.Config) {
			cfg.Resolve = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}
			d := &net.Dialer{KeepAlive: -1}
			cfg.DialTCP = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			}
		}
	}
	if v, err := time.ParseDuration(os.Getenv("SEAWISE_TEST_LIST_EVERY")); err == nil && v > 0 {
		testAppSyncConfig = func(cfg *appsync.Config) { cfg.ListEvery = v }
	}
}

// testRoots reads keyset-roots.json, else keyset-root, from dir; nil when
// neither exists. A file that is there but unusable stops the process: a
// test build silently running without its roots would hide the mistake.
func testRoots(dir string) []ed25519.PublicKey {
	b, err := os.ReadFile(filepath.Join(dir, "keyset-roots.json"))
	if err == nil {
		roots, perr := keyset.ParseRoots(b)
		if perr != nil || len(roots) == 0 {
			panic(fmt.Sprintf("SEAWISE_TEST_TUF_DIR: keyset-roots.json holds no usable roots: %v", perr))
		}
		return roots
	}
	if !errors.Is(err, fs.ErrNotExist) {
		panic("SEAWISE_TEST_TUF_DIR: keyset-roots.json: " + err.Error())
	}
	b, err = os.ReadFile(filepath.Join(dir, "keyset-root"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		panic("SEAWISE_TEST_TUF_DIR: keyset-root: " + err.Error())
	}
	pub, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		panic("SEAWISE_TEST_TUF_DIR: keyset-root is not a base64url Ed25519 public key")
	}
	return []ed25519.PublicKey{pub}
}
