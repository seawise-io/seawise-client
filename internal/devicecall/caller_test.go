package devicecall

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/protocol"
)

var testKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))

const (
	nonceA = "n1.AAAAAA.AAAAAAAAAAAAAAAAAAAAAA"
	nonceB = "n1.AAAAAQ.AAAAAAAAAAAAAAAAAAAAAA"
)

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (s *seen) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.body = append(s.body, b)
	s.mu.Unlock()
}

func (s *seen) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func proofClaims(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	parts := strings.Split(r.Header.Get("DPoP"), ".")
	if len(parts) != 3 {
		t.Fatal("proof segments")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c protocol.DPoPClaims
	if err != nil || json.Unmarshal(raw, &c) != nil {
		t.Fatal("proof payload")
	}
	return map[string]any{"htm": c.HTM, "htu": c.HTU, "nonce": c.Nonce, "jti": c.JTI, "iat": c.IAT}
}

func newTest(t *testing.T, h http.HandlerFunc) (*Caller, *httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{Client: srv.Client(), Version: "2.0.0", Now: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return c, srv, s
}

func TestCheckOrigin(t *testing.T) {
	good := map[string]string{"https://api.seawise.io": "https://api.seawise.io", "https://api.seawise.io/": "https://api.seawise.io", "https://h:8443": "https://h:8443"}
	for in, want := range good {
		if got, err := CheckOrigin(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"http://api.seawise.io", "https://", "https://u@h", "https://h/x", "https://h?q", "https://h?", "https://h#f", "ftp://h", "", "https:h", "https://:443", "%"} {
		if _, err := CheckOrigin(in); !errors.Is(err, ErrInsecureOrigin) {
			t.Errorf("%s accepted", in)
		}
	}
}

func TestInsecureClientRefused(t *testing.T) {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- the refusal is under test
	if _, err := New(Config{Client: c}); !errors.Is(err, ErrInsecureTLS) {
		t.Fatal("insecure client accepted")
	}
	if _, err := New(Config{Client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}}); err != nil {
		t.Fatal(err)
	}
	c2, err := New(Config{})
	if err != nil || c2.client.Timeout != 30*time.Second || c2.now == nil || c2.jti == nil {
		t.Fatal("defaults")
	}
}

func TestRequestShape(t *testing.T) {
	c, srv, s := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", nonceA)
		_, _ = w.Write([]byte(`{"ok":"1"}`))
	})
	body := []byte(`{"a":"b"}`)
	a, err := c.Do(context.Background(), testKey, srv.URL, http.MethodPost, "/x/y", body, map[string]string{"X-Extra": "1", "DPoP": "forged", "User-Agent": "forged"})
	if err != nil || a.Status != 200 || string(a.Body) != `{"ok":"1"}` {
		t.Fatalf("%+v %v", a, err)
	}
	r := s.reqs[0]
	cl := proofClaims(t, r)
	if cl["htm"] != "POST" || cl["htu"] != srv.URL+"/x/y" || cl["nonce"] != "none" || cl["iat"] != int64(1_800_000_000) {
		t.Fatalf("claims %v", cl)
	}
	if r.Header.Get("User-Agent") != "seawise-agent/2.0.0" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Extra") != "1" || string(s.body[0]) != string(body) {
		t.Fatalf("headers %v", r.Header)
	}
	if _, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/g", nil, map[string]string{"Content-Type": "text/plain"}); err != nil {
		t.Fatal(err)
	}
	g := s.reqs[1]
	if g.Header.Get("Content-Type") != "" || len(s.body[1]) != 0 || proofClaims(t, g)["nonce"] != nonceA {
		t.Fatalf("GET %v", g.Header)
	}
	if proofClaims(t, g)["jti"] == cl["jti"] {
		t.Fatal("jti reused")
	}
}

func TestNonceChallengeRetriedOnce(t *testing.T) {
	for _, viaBody := range []bool{false, true} {
		var n atomic.Int32
		c, srv, s := newTest(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("DPoP-Nonce", nonceB)
			if n.Add(1) <= 2 {
				if !viaBody {
					w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				}
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		})
		a, err := c.Do(context.Background(), testKey, srv.URL, http.MethodPost, "/p", []byte(`{}`), nil)
		if err != nil || a.Status != 401 || s.n() != 2 {
			t.Fatalf("viaBody %v: %+v %v %d calls", viaBody, a, err, s.n())
		}
		if proofClaims(t, s.reqs[1])["nonce"] != nonceB {
			t.Fatal("retry without the new nonce")
		}
		a, err = c.Do(context.Background(), testKey, srv.URL, http.MethodPost, "/p", []byte(`{}`), nil)
		if err != nil || a.Status != 200 || s.n() != 3 {
			t.Fatalf("%+v %v", a, err)
		}
	}
}

func TestChallengeNeedsValidNonce(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"no nonce": func(w http.ResponseWriter) {
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(401)
		},
		"bad nonce": func(w http.ResponseWriter) {
			w.Header().Set("DPoP-Nonce", "x y")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(401)
		},
		"other 401": func(w http.ResponseWriter) {
			w.Header().Set("DPoP-Nonce", nonceA)
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_proof"}`))
		},
		"not 401": func(w http.ResponseWriter) {
			w.Header().Set("DPoP-Nonce", nonceA)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(400)
		},
	}
	for name, h := range cases {
		c, srv, s := newTest(t, func(w http.ResponseWriter, r *http.Request) { h(w) })
		if _, err := c.Do(context.Background(), testKey, srv.URL, http.MethodPost, "/p", nil, nil); err != nil || s.n() != 1 {
			t.Errorf("%s: %v, %d calls", name, err, s.n())
		}
	}
}

func TestInvalidNonceNotKept(t *testing.T) {
	c, srv, s := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "not a nonce")
	})
	c.KeepNonce(nonceA)
	for i := 0; i < 2; i++ {
		if _, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/g", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if proofClaims(t, s.reqs[1])["nonce"] != nonceA {
		t.Fatal("invalid nonce replaced the kept one")
	}
}

func TestRetryAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "0": 0, "-3": 0, "x": 0, "5": 5 * time.Second, "3600": time.Hour, "3601": time.Hour, "99999999": time.Hour} {
		c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
			if in != "" {
				w.Header().Set("Retry-After", in)
			}
			w.WriteHeader(429)
		})
		a, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/g", nil, nil)
		if err != nil || a.RetryAfter != want || a.Status != 429 {
			t.Errorf("%q: %v %v", in, a.RetryAfter, err)
		}
	}
}

func TestAnswerSizeCap(t *testing.T) {
	for _, size := range []int{MaxAnswer, MaxAnswer + 1} {
		c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat(" ", size)))
		})
		a, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/g", nil, nil)
		if (err != nil) != (size > MaxAnswer) || (err == nil && len(a.Body) != size) {
			t.Fatalf("size %d: %v", size, err)
		}
		if err != nil && !strings.Contains(err.Error(), "too large") {
			t.Fatal(err)
		}
	}
}

func TestAnswerCutShort(t *testing.T) {
	c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("abc"))
	})
	if _, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/g", nil, nil); err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Fatal(err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	defer other.Close()
	c, srv, _ := newTest(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	a, err := c.Do(context.Background(), testKey, srv.URL, http.MethodPost, "/p", []byte(`{}`), map[string]string{"X-Secret": "s"})
	if err != nil || a.Status != http.StatusTemporaryRedirect || leaked.Load() {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c, err := New(Config{Client: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), testKey, srv.URL, http.MethodGet, "/", nil, nil); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatal(err)
	}
}

func TestSignAndRequestErrors(t *testing.T) {
	c, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), badSigner{}, "https://h", http.MethodGet, "/", nil, nil); err == nil || !strings.Contains(err.Error(), "sign proof") {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), testKey, "https://h", "BAD METHOD", "/", nil, nil); err == nil {
		t.Fatal("bad method accepted")
	}
}

func TestParseRefusal(t *testing.T) {
	if r := ParseRefusal([]byte(`{"error":"a","code":"b"}`)); r.Error != "a" || r.Code != "b" {
		t.Fatal(r)
	}
	if r := ParseRefusal([]byte(`{"error":1}`)); r != (Refusal{}) {
		t.Fatal(r)
	}
}

func TestNewJTI(t *testing.T) {
	a, b := NewJTI(), NewJTI()
	if a == b || len(a) != 22 || !protocol.ValidID(a) {
		t.Fatalf("%q %q", a, b)
	}
}

type badSigner struct{}

func (badSigner) Public() crypto.PublicKey { return testKey.Public() }
func (badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("no")
}
