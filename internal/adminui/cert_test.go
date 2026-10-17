package adminui

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestEnsureCertCreatesAndReuses(t *testing.T) {
	dir := t.TempDir()
	names := []string{"localhost", "nas", "nas.local"}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("192.168.1.10")}
	a, err := EnsureCert(dir, names, ips, time.Now())
	if err != nil || !a.Regenerated {
		t.Fatal(a, err)
	}
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(a.Fingerprint) {
		t.Fatalf("fingerprint %q", a.Fingerprint)
	}
	for _, f := range []string{CertFile, KeyFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
	}
	leaf := a.Cert.Leaf
	if leaf.IsCA || leaf.NotAfter.Sub(leaf.NotBefore) > CertValidity+2*time.Hour {
		t.Fatalf("cert profile %+v", leaf)
	}
	b, err := EnsureCert(dir, names, ips, time.Now())
	if err != nil || b.Regenerated || b.Fingerprint != a.Fingerprint {
		t.Fatalf("not reused: %v", err)
	}
}

func TestCertRegeneratesOnNewIP(t *testing.T) {
	dir := t.TempDir()
	a, _ := EnsureCert(dir, []string{"localhost"}, []net.IP{net.ParseIP("192.168.1.10")}, time.Now())
	b, err := EnsureCert(dir, []string{"localhost"}, []net.IP{net.ParseIP("192.168.1.11")}, time.Now())
	if err != nil || !b.Regenerated || a.Fingerprint == b.Fingerprint {
		t.Fatal("not regenerated for a new address")
	}
	c, _ := EnsureCert(dir, []string{"localhost", "new-name"}, []net.IP{net.ParseIP("192.168.1.11")}, time.Now())
	if !c.Regenerated {
		t.Fatal("not regenerated for a new name")
	}
}

func TestCertRegeneratesNearExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	EnsureCert(dir, []string{"localhost"}, nil, now)
	b, err := EnsureCert(dir, []string{"localhost"}, nil, now.Add(CertValidity-CertRenewal+time.Hour))
	if err != nil || !b.Regenerated {
		t.Fatal("not renewed near expiry")
	}
}

func TestCertRegeneratesWhenCorrupt(t *testing.T) {
	dir := t.TempDir()
	EnsureCert(dir, []string{"localhost"}, nil, time.Now())
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := EnsureCert(dir, []string{"localhost"}, nil, time.Now())
	if err != nil || !b.Regenerated {
		t.Fatal("corrupt key not replaced")
	}
}

func TestCertRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	EnsureCert(dir, []string{"localhost"}, nil, time.Now())
	other := filepath.Join(t.TempDir(), "x")
	os.WriteFile(other, []byte("x"), 0o600)
	os.Remove(filepath.Join(dir, CertFile))
	if err := os.Symlink(other, filepath.Join(dir, CertFile)); err != nil {
		t.Skip(err)
	}
	if _, err := loadCert(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)); err == nil {
		t.Fatal("symlinked cert loaded")
	}
}

func TestSanitizeNames(t *testing.T) {
	got := sanitizeNames([]string{"NAS", "nas.", "*.evil", "a b", "10.0.0.1", "-x", "good-host.lan", "", "x:8082"})
	want := []string{"good-host.lan", "nas"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("%v", got)
	}
}
