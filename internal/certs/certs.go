package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// validDomain matches only safe domain characters: alphanumeric, hyphens, dots.
// Rejects path traversal attempts like "../" or absolute paths.
var validDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// CertManager handles certificate generation and storage
type CertManager struct {
	certsDir string
}

// CertInfo contains paths to certificate and key files
type CertInfo struct {
	CertPath   string
	KeyPath    string
	Domain     string
	ExpiresAt  time.Time
	IssuedAt   time.Time
}

// New creates a new CertManager
func New(baseDir string) *CertManager {
	certsDir := filepath.Join(baseDir, "certs")
	return &CertManager{certsDir: certsDir}
}

// EnsureDir creates the certs directory if it doesn't exist
func (m *CertManager) EnsureDir() error {
	return os.MkdirAll(m.certsDir, 0700)
}

// validateDomain ensures the domain name is safe for use in file paths.
// Prevents path traversal attacks from malicious subdomain values.
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("empty domain")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long: %d chars", len(domain))
	}
	if !validDomain.MatchString(domain) {
		return fmt.Errorf("invalid domain characters: %s", domain)
	}
	return nil
}

// GenerateKey generates a new ECDSA private key
func (m *CertManager) GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CreateCSR creates a Certificate Signing Request for the given domain
func (m *CertManager) CreateCSR(key *ecdsa.PrivateKey, domain string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"SeaWise User"},
		},
		DNSNames: []string{domain},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// SaveKey saves the private key to disk
func (m *CertManager) SaveKey(key *ecdsa.PrivateKey, domain string) (string, error) {
	if err := validateDomain(domain); err != nil {
		return "", fmt.Errorf("invalid domain for key: %w", err)
	}
	if err := m.EnsureDir(); err != nil {
		return "", err
	}

	keyPath := filepath.Join(m.certsDir, domain+".key")

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", fmt.Errorf("failed to write private key: %w", err)
	}

	return keyPath, nil
}

// SaveCert saves the certificate to disk
func (m *CertManager) SaveCert(certPEM []byte, domain string) (string, error) {
	if err := validateDomain(domain); err != nil {
		return "", fmt.Errorf("invalid domain for cert: %w", err)
	}
	if err := m.EnsureDir(); err != nil {
		return "", err
	}

	certPath := filepath.Join(m.certsDir, domain+".crt")

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", fmt.Errorf("failed to write certificate: %w", err)
	}

	return certPath, nil
}

// LoadKey loads a private key from disk
func (m *CertManager) LoadKey(domain string) (*ecdsa.PrivateKey, error) {
	if err := validateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain for key load: %w", err)
	}
	keyPath := filepath.Join(m.certsDir, domain+".key")

	keyPEM, err := os.ReadFile(keyPath) // nosec G304 — domain validated by validateDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

// LoadCert loads a certificate from disk and returns its info
func (m *CertManager) LoadCert(domain string) (*CertInfo, error) {
	if err := validateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain for cert load: %w", err)
	}
	certPath := filepath.Join(m.certsDir, domain+".crt")
	keyPath := filepath.Join(m.certsDir, domain+".key")

	certPEM, err := os.ReadFile(certPath) // nosec G304 — domain validated by validateDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertInfo{
		CertPath:  certPath,
		KeyPath:   keyPath,
		Domain:    domain,
		ExpiresAt: cert.NotAfter,
		IssuedAt:  cert.NotBefore,
	}, nil
}

// CertExists checks if a certificate exists for the domain
func (m *CertManager) CertExists(domain string) bool {
	if err := validateDomain(domain); err != nil {
		return false
	}

	certPath := filepath.Join(m.certsDir, domain+".crt")
	keyPath := filepath.Join(m.certsDir, domain+".key")

	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// NeedsRenewal checks if a certificate needs renewal (expires within 30 days)
func (m *CertManager) NeedsRenewal(domain string) bool {
	info, err := m.LoadCert(domain)
	if err != nil {
		return true // If we can't load it, we need a new one
	}

	// Renew if expiring within 30 days
	renewalWindow := 30 * 24 * time.Hour
	return time.Until(info.ExpiresAt) < renewalWindow
}

// GetCertPaths returns the paths to cert and key for a domain
func (m *CertManager) GetCertPaths(domain string) (certPath, keyPath string, err error) {
	if err := validateDomain(domain); err != nil {
		return "", "", err
	}
	return filepath.Join(m.certsDir, domain+".crt"),
		filepath.Join(m.certsDir, domain+".key"), nil
}

// DeleteCert removes certificate and key files for a domain
func (m *CertManager) DeleteCert(domain string) error {
	if err := validateDomain(domain); err != nil {
		return err
	}

	certPath := filepath.Join(m.certsDir, domain+".crt")
	keyPath := filepath.Join(m.certsDir, domain+".key")

	var firstErr error
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		firstErr = fmt.Errorf("failed to remove cert: %w", err)
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = fmt.Errorf("failed to remove key: %w", err)
	}
	return firstErr
}
