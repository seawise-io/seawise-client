package enrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

const testServer = "6f1d2c3b-4a59-4687-9a1b-2c3d4e5f6a7b"

var testToken = func() string {
	d := sha256.Sum256([]byte("a 1.x token"))
	return hex.EncodeToString(d[:])
}()

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t       *testing.T
	dir     string
	st      *store.Store
	ks      identity.Keystore
	fake    *fakeC12
	srv     *httptest.Server
	e       *Enroller
	logs    *syncBuf
	clk     *clock
	origin  string
	changes int
	v1      map[string][]byte
	handler atomic.Pointer[handlerBox]
	// jti fixes the proof id while set.
	jti atomic.Pointer[string]
	// client replaces the test server's client when set.
	client *http.Client
}

type handlerBox struct{ h http.Handler }

// serve replaces what the test server answers with.
func (v *env) serve(h http.HandlerFunc) { v.handler.Store(&handlerBox{h}) }

func writeV1(t *testing.T, dir, token, apiURL string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"account.json": []byte(`{"server_id":"` + testServer + `","server_name":"nas","frp_token":"` + token + `","frp_server_addr":"frp.seawise.io","frp_server_port":7000,"frp_use_tls":true,"api_url":"` + apiURL + `","user_id":"u1","user_email":"owner@example.com"}`),
		"machine.json": []byte(`{"machine_id":"m1","machine_name":"nas","services":[{"local_id":"0123456789abcdef0123456789abcdef","name":"jellyfin","host":"127.0.0.1","port":8096,"subdomain":"jf-abc"}]}`),
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func newEnv(t *testing.T) *env {
	return newEnvToken(t, testToken)
}

func newEnvToken(t *testing.T, token string) *env {
	t.Helper()
	fake := newFake(testServer, token)
	v := &env{t: t, dir: t.TempDir(), fake: fake, logs: &syncBuf{}, clk: &clock{t: time.Unix(1_800_000_000, 0)}}
	v.handler.Store(&handlerBox{fake})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { v.handler.Load().h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	fake.publicURL, v.srv, v.origin = srv.URL, srv, srv.URL
	v.v1 = writeV1(t, v.dir, token, srv.URL)
	v.open()
	t.Cleanup(v.close)
	return v
}

func (v *env) open() {
	v.t.Helper()
	st, err := store.Open(v.dir, v.clk.now)
	if err != nil {
		v.t.Fatal(err)
	}
	ks, err := identity.OpenFile(st.Dir(), v.clk.now)
	if err != nil {
		st.Close()
		v.t.Fatal(err)
	}
	v.st, v.ks = st, ks
	client := v.srv.Client()
	if v.client != nil {
		client = v.client
	}
	call, err := devicecall.New(devicecall.Config{Client: client, Version: "2.0.0", Now: v.clk.now, JTI: func() string {
		if j := v.jti.Load(); j != nil {
			return *j
		}
		return devicecall.NewJTI()
	}})
	if err != nil {
		v.t.Fatal(err)
	}
	e, err := New(Config{
		Store: st, Keys: ks, Origin: func() string { return v.origin }, Caller: call,
		Now: v.clk.now, Logger: slog.New(slog.NewTextHandler(v.logs, nil)),
		OnChange: func(context.Context) { v.changes++ }, Jitter: func() float64 { return 1 },
	})
	if err != nil {
		v.t.Fatal(err)
	}
	v.e = e
}

func (v *env) close() {
	if v.ks != nil {
		v.ks.Close()
		v.ks = nil
	}
	if v.st != nil {
		v.st.Close()
		v.st = nil
	}
}

// reopen simulates a restart.
func (v *env) reopen() {
	v.close()
	v.open()
}

func (v *env) step() time.Duration { return v.e.Step(context.Background()) }

// run steps until done reports true, at most n steps.
func (v *env) run(n int, done func() bool) {
	v.t.Helper()
	for i := 0; i < n; i++ {
		if done() {
			return
		}
		v.step()
	}
	if !done() {
		v.t.Fatalf("not done after %d steps: %+v", n, v.e.Status())
	}
}

func (v *env) switched() bool {
	r := v.st.State().EnrolmentFor()
	return r != nil && r.Phase == store.PhaseSwitched && v.st.Secrets().FRPToken == ""
}

func (v *env) phase() string {
	if r := v.st.State().EnrolmentFor(); r != nil {
		return r.Phase
	}
	return ""
}

func (v *env) holdReason() string {
	if r := v.st.State().EnrolmentFor(); r != nil {
		return r.Hold
	}
	return ""
}

// intact checks that the account, apps and v1 files are as imported.
func (v *env) intact() {
	v.t.Helper()
	st := v.st.State()
	if st.Account == nil || st.Account.ServerID != testServer || len(st.Targets) != 1 || st.Targets[0].Name != "jellyfin" {
		v.t.Fatalf("account or apps changed: %+v", st)
	}
	for n, b := range v.v1 {
		got, err := os.ReadFile(filepath.Join(v.dir, n))
		if err != nil || !bytes.Equal(got, b) {
			v.t.Fatalf("v1 file %s changed", n)
		}
	}
	if bytes.Contains([]byte(v.logs.String()), []byte(testToken)) {
		v.t.Fatal("token in logs")
	}
}

var _ http.Handler = (*fakeC12)(nil)
