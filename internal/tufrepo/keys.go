package tufrepo

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// GenerateKey returns a new Ed25519 signing key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	return k, err
}

// MarshalPrivateKey encodes k as PKCS#8 PEM.
func MarshalPrivateKey(k ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKey encodes k as PKIX PEM.
func MarshalPublicKey(k ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKey decodes a PKCS#8 PEM Ed25519 key.
func ParsePrivateKey(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return ek, nil
}

// ParsePublicKey decodes a PKIX PEM Ed25519 public key.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		return nil, errors.New("not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return ek, nil
}

// KeyID is the TUF key ID of k.
func KeyID(k ed25519.PublicKey) (string, error) {
	tk, err := metadata.KeyFromPublicKey(k)
	if err != nil {
		return "", err
	}
	return tk.ID()
}

// Keygen writes a new private key to path (0600, never overwritten) and its
// public key to path+".pub", and returns the key ID.
func Keygen(path string) (string, error) {
	k, err := GenerateKey()
	if err != nil {
		return "", err
	}
	if err := writeKey(path, k); err != nil {
		return "", err
	}
	return KeyID(k.Public().(ed25519.PublicKey))
}

// writeKey creates path (0600) and path+".pub"; neither may exist.
func writeKey(path string, k ed25519.PrivateKey) error {
	priv, err := MarshalPrivateKey(k)
	if err != nil {
		return err
	}
	pubPEM, err := MarshalPublicKey(k.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	// Public keys are meant to be shared, so 0644.
	if err := createExcl(path+".pub", pubPEM, 0o644); err != nil { // #nosec G306 -- public key
		return err
	}
	if err := createExcl(path, priv, 0o600); err != nil {
		_ = os.Remove(path + ".pub")
		return err
	}
	return nil
}

func createExcl(path string, data []byte, perm os.FileMode) error {
	// #nosec G304 -- operator-chosen output path; O_EXCL never replaces a file
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// LoadPrivateKey reads a key from a file, or from an environment variable
// when ref is "env:NAME".
func LoadPrivateKey(ref string, getenv func(string) string) (ed25519.PrivateKey, error) {
	var b []byte
	if name, ok := strings.CutPrefix(ref, "env:"); ok {
		v := getenv(name)
		if v == "" {
			return nil, fmt.Errorf("environment variable %s is empty", name)
		}
		b = []byte(v)
	} else {
		var err error
		if b, err = os.ReadFile(ref); err != nil { // #nosec G304 -- operator-chosen key file
			return nil, err
		}
	}
	k, err := ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", strings.SplitN(ref, ":", 2)[0], err)
	}
	return k, nil
}

// LoadPublicKey reads a PKIX PEM public key file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-chosen key file
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(b)
}

// ParseDuration accepts Go durations plus a whole number of days ("14d").
func ParseDuration(s string) (time.Duration, error) {
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}
