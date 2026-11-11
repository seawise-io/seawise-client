// Package testedge is a protocol-level stand-in for the SeaWise edge and
// device API, for tests that run the released agent binary: the tunnel
// listener (raw TLS and the WebSocket carriage), edge-signed HelloAck and
// RouteSet, device calls answered with device API bodies on stream 0 and
// over HTTPS, a signed update repository carrying the key set, a traffic
// meter on every tunnel connection and controls for fault tests.
//
// It is test code: nothing in the agent imports it.
package testedge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA issues server certificates whose validity follows a clock.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// NewCA makes a CA valid from 2000 to 2100, so no clock offset a test uses
// makes the root itself invalid.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "testedge root"},
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: c, key: key, der: der, cache: map[string]*tls.Certificate{}}, nil
}

// PEM is the root certificate, for SSL_CERT_FILE.
func (ca *CA) PEM() []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der}) }

// Pool holds the root.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

// Leaf returns a certificate for name (a DNS name or an IP) issued age
// before now and valid for 90 days, as an ACME certificate would be.
func (ca *CA) Leaf(name string, now time.Time, age time.Duration) (*tls.Certificate, error) {
	from := now.Add(-age).Truncate(time.Minute)
	k := name + "|" + from.Format(time.RFC3339)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[k]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: from, NotAfter: from.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.der}, PrivateKey: key}
	ca.cache[k] = c
	return c, nil
}
