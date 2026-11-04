//go:build seawise_tuftest

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
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

// Built only by the budget tests and the network fault suite. Files in
// SEAWISE_TEST_TUF_DIR: root.json, url and ca.pem for the update check,
// keyset-root (base64url Ed25519 key) for the key set. SEAWISE_TEST_EDGE_ADDR
// sends tunnel dials to that address; SEAWISE_TEST_LIST_EVERY shortens
// the app list period.
func init() {
	dir := os.Getenv("SEAWISE_TEST_TUF_DIR")
	testUpdateConfig = func(cfg *updatecheck.Config) {
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
		if dir == "" {
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, "keyset-root"))
		if err != nil {
			return
		}
		pub, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return
		}
		cfg.Roots, cfg.AllowTestRoots = []ed25519.PublicKey{pub}, true
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
