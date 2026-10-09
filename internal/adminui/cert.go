package adminui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/seawise/client/internal/store"
)

const (
	CertFile      = "admin-cert.pem"
	KeyFile       = "admin-key.pem"
	CertValidity  = 397 * 24 * time.Hour
	CertRenewal   = 30 * 24 * time.Hour
	maxCertNames  = 64
	maxDNSNameLen = 253
)

type CertInfo struct {
	Cert        tls.Certificate
	Fingerprint string
	NotAfter    time.Time
	Regenerated bool
}

// LocalNames returns the names and addresses the admin certificate should
// cover on this machine.
func LocalNames(hostname string, extra []string) ([]string, []net.IP) {
	names := []string{"localhost"}
	if hostname != "" {
		names = append(names, hostname, hostname+".local")
	}
	names = sanitizeNames(append(names, extra...))
	ips := []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.IPv6loopback}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsMulticast() || ipn.IP.IsUnspecified() {
				continue
			}
			ips = append(ips, ipn.IP)
		}
	}
	return names, dedupeIPs(ips)
}

// sanitizeNames keeps lower-case DNS names (no IP literals, wildcards or
// ports), deduplicated and sorted, at most maxCertNames.
func sanitizeNames(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range in {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if !validDNSName(n) || seen[n] {
			continue
		}
		if _, err := netip.ParseAddr(n); err == nil {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > maxCertNames {
		out = out[:maxCertNames]
	}
	return out
}

func validDNSName(n string) bool {
	if n == "" || len(n) > maxDNSNameLen {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func dedupeIPs(in []net.IP) []net.IP {
	seen := map[string]bool{}
	out := []net.IP{}
	for _, ip := range in {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		k := ip.String()
		if ip == nil || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ip)
	}
	return out
}

// EnsureCert loads the admin certificate from dir, or creates a new one when
// it is missing, unreadable, close to expiry or does not cover every name and
// address given.
func EnsureCert(dir string, names []string, ips []net.IP, now time.Time) (*CertInfo, error) {
	names = sanitizeNames(names)
	ips = dedupeIPs(ips)
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	if info, err := loadCert(certPath, keyPath); err == nil {
		leaf := info.Cert.Leaf
		if now.Add(CertRenewal).Before(leaf.NotAfter) && !now.Before(leaf.NotBefore) && covers(leaf, names, ips) {
			return info, nil
		}
	}
	info, err := generateCert(names, ips, now)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(info.Cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	if err := store.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return nil, err
	}
	if err := store.WriteFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: info.Cert.Certificate[0]}), 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return nil, err
	}
	info.Regenerated = true
	return info, nil
}

func loadCert(certPath, keyPath string) (*CertInfo, error) {
	for _, p := range []string{certPath, keyPath} {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &CertInfo{Cert: cert, Fingerprint: Fingerprint(cert.Certificate[0]), NotAfter: cert.Leaf.NotAfter}, nil
}

func covers(leaf *x509.Certificate, names []string, ips []net.IP) bool {
	have := map[string]bool{}
	for _, n := range leaf.DNSNames {
		have[strings.ToLower(n)] = true
	}
	for _, n := range names {
		if !have[n] {
			return false
		}
	}
	for _, ip := range ips {
		found := false
		for _, c := range leaf.IPAddresses {
			if c.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func generateCert(names []string, ips []net.IP, now time.Time) (*CertInfo, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "SeaWise local admin", Organization: []string{"SeaWise client"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CertInfo{
		Cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		Fingerprint: Fingerprint(der),
		NotAfter:    leaf.NotAfter,
	}, nil
}

// Fingerprint is the SHA-256 of the DER certificate as colon-separated hex,
// the form browsers show.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
