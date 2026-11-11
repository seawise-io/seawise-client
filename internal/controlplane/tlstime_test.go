package controlplane

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTransportChecksCertificatesOnItsClock(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	noEnv := func(string) string { return "" }
	get := func(tr *http.Transport) error {
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(NewTransportAt(noEnv, roots, nil)); err != nil {
		t.Fatal("system clock:", err)
	}
	if err := get(NewTransportAt(noEnv, roots, time.Now)); err != nil {
		t.Fatal("given clock:", err)
	}
	// The test certificate expires in 2084.
	err := get(NewTransportAt(noEnv, roots, func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) }))
	var inv x509.CertificateInvalidError
	if !errors.As(err, &inv) || inv.Reason != x509.Expired {
		t.Fatal("certificate checked against another clock:", err)
	}
	if NewTransport(noEnv, roots).TLSClientConfig.Time != nil {
		t.Fatal("NewTransport set a clock")
	}
}

func TestRetryTransportRetriesOnceAfterExpiredCertificate(t *testing.T) {
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
	}))
	t.Cleanup(srv.Close)
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	noEnv := func(string) string { return "" }
	late := func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) }
	post := func(rt http.RoundTripper) error {
		resp, err := (&http.Client{Transport: rt}).Post(srv.URL, "application/json", strings.NewReader(`{"a":1}`))
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	asked := 0
	rt := NewTransportRetry(noEnv, roots, late, func() (time.Time, bool) { asked++; return time.Now(), true })
	if err := post(rt); err != nil || asked != 1 || len(bodies) != 1 || bodies[0] != `{"a":1}` {
		t.Fatalf("retry: %v asked %d bodies %q", err, asked, bodies)
	}
	if p, ok := rt.(interface{ Primary() *http.Transport }); !ok || p.Primary().TLSClientConfig.Time == nil {
		t.Fatal("primary transport not exposed")
	}
	rt = NewTransportRetry(noEnv, roots, late, func() (time.Time, bool) { return time.Time{}, false })
	var inv x509.CertificateInvalidError
	if err := post(rt); !errors.As(err, &inv) {
		t.Fatal("no retry time, want the expiry error:", err)
	}
	asked = 0
	rt = NewTransportRetry(noEnv, x509.NewCertPool(), nil, func() (time.Time, bool) { asked++; return time.Now(), true })
	if err := post(rt); err == nil || asked != 0 {
		t.Fatal("untrusted root retried:", err)
	}
	if _, ok := NewTransportRetry(noEnv, roots, nil, nil).(*http.Transport); !ok {
		t.Fatal("no retry should give the plain transport")
	}
}
