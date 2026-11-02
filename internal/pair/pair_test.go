package pair

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

const (
	testUser   = "a0000000-0000-4000-8000-000000000001"
	v1Server   = "6f1d2c3b-4a59-4687-9a1b-2c3d4e5f6a7b"
	v1Token    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	jellyfinID = "0123456789abcdef0123456789abcdef"
)

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
	t      *testing.T
	dir    string
	st     *store.Store
	ks     identity.Keystore
	fake   *fakePairing
	srv    *httptest.Server
	p      *Pairer
	logs   *syncBuf
	clk    *clock
	origin string
	paired atomic.Int32
	ctx    context.Context
}

func newEnv(t *testing.T) *env {
	return newEnvDir(t, t.TempDir())
}

func newEnvDir(t *testing.T, dir string) *env {
	t.Helper()
	v := &env{t: t, dir: dir, fake: newFakePairing(), logs: &syncBuf{}, clk: &clock{t: time.Now()}}
	v.fake.now = v.clk.now
	v.srv = httptest.NewTLSServer(v.fake)
	t.Cleanup(v.srv.Close)
	v.fake.publicURL, v.origin = v.srv.URL, v.srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v.ctx = ctx
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
	call, err := devicecall.New(devicecall.Config{Client: v.srv.Client(), Version: "2.0.0"})
	if err != nil {
		v.t.Fatal(err)
	}
	p, err := New(Config{
		Context: v.ctx, Store: st, Keys: ks, Caller: call, Origin: func() string { return v.origin },
		WebURL: "https://seawise.io", Now: v.clk.now, Poll: 2 * time.Millisecond,
		Logger:   slog.New(slog.NewTextHandler(v.logs, nil)),
		OnPaired: func(context.Context) { v.paired.Add(1) },
	})
	if err != nil {
		v.t.Fatal(err)
	}
	v.p = p
}

func (v *env) close() {
	if v.p != nil {
		v.p.Cancel()
	}
	if v.ks != nil {
		v.ks.Close()
		v.ks = nil
	}
	if v.st != nil {
		v.st.Close()
		v.st = nil
	}
}

func (v *env) wait(what string, done func() bool) {
	v.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: timed out; status %+v", what, v.p.Status())
		}
		time.Sleep(time.Millisecond)
	}
}

func (v *env) state(s string) func() bool {
	return func() bool { return v.p.Status().State == s }
}

func (v *env) start() Status {
	v.t.Helper()
	s, err := v.p.Start(context.Background(), "nas")
	if err != nil {
		v.t.Fatal(err)
	}
	return s
}

func (v *env) key() *identity.Key {
	v.t.Helper()
	k, err := v.ks.Current()
	if err != nil {
		v.t.Fatal(err)
	}
	return k
}

// noSecrets checks that no code, token or proof reached the logs, and
// that no 1.x credential was sent.
func (v *env) noSecrets() {
	v.t.Helper()
	logs := v.logs.String()
	v.fake.with(func(f *fakePairing) {
		for _, r := range f.byDevice {
			if strings.Contains(logs, r.user) || strings.Contains(logs, r.device) {
				v.t.Fatal("pairing code in logs")
			}
		}
		for _, h := range f.headers {
			if h.Get("X-FRP-Token") != "" || h.Get("Authorization") != "" {
				v.t.Fatal("credential header sent")
			}
			if strings.Contains(logs, h.Get("DPoP")) {
				v.t.Fatal("proof in logs")
			}
		}
	})
	if strings.Contains(logs, v1Token) {
		v.t.Fatal("1.x token in logs")
	}
}

func writeV1(t *testing.T, dir, apiURL string) {
	t.Helper()
	files := map[string]string{
		"account.json": `{"server_id":"` + v1Server + `","server_name":"old","frp_token":"` + v1Token + `","frp_server_addr":"frp.seawise.io","frp_server_port":7000,"frp_use_tls":true,"api_url":"` + apiURL + `","user_id":"u1"}`,
		"machine.json": `{"machine_id":"m1","machine_name":"nas","services":[{"local_id":"` + jellyfinID + `","name":"jellyfin","host":"127.0.0.1","port":8096,"subdomain":"jf-abc","server_service_id":"11111111-1111-4111-8111-111111111111"}]}`,
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPairFlow(t *testing.T) {
	v := newEnv(t)
	s := v.start()
	k := v.key()
	if s.State != StatePending || !userCodeRe.MatchString(s.Code) || s.KeyFingerprint != k.Fingerprint() || s.ApproveURL != "https://seawise.io/connect" || strings.Contains(s.ApproveURL, s.Code) || s.ExpiresAt.IsZero() {
		t.Fatalf("status %+v", s)
	}
	if got := v.p.Status(); got != s {
		t.Fatalf("status %+v, want %+v", got, s)
	}
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 2 })
	if v.p.Status().State != StatePending || v.st.State().Account != nil {
		t.Fatal("paired before approval")
	}
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	acc := v.st.State().Account
	if acc == nil || acc.KeyID != k.KeyID() || acc.DeviceID == "" || acc.APIURL != v.origin || acc.ServerName != "nas" || acc.UserID != testUser || !acc.Keyed() {
		t.Fatalf("account %+v", acc)
	}
	if v.st.State().EnrolmentNeeded(v.st.Secrets()) || v.st.Secrets().FRPToken != "" {
		t.Fatal("paired account needs a 1.x token or enrolment")
	}
	v.wait("OnPaired", func() bool { return v.paired.Load() == 1 })
	if v.p.Status().ServerName != "nas" {
		t.Fatalf("OnPaired %d, status %+v", v.paired.Load(), v.p.Status())
	}
	for _, path := range []string{PathRequest, PathStatus, PathComplete} {
		for _, kid := range v.fake.keyIDs(path) {
			if kid != k.KeyID() {
				t.Fatalf("%s signed by another key", path)
			}
		}
	}
	if v.fake.count(PathCancel) != 0 {
		t.Fatal("cancel sent after pairing")
	}
	v.noSecrets()
	if _, err := v.p.Start(context.Background(), "again"); !errors.Is(err, ErrPaired) {
		t.Fatalf("second pairing: %v", err)
	}
	if v.key().KeyID() != k.KeyID() {
		t.Fatal("key replaced while paired")
	}
}

func TestPairingSurvivesRestart(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	kid := v.key().KeyID()
	v.close()
	v.open()
	if acc := v.st.State().Account; acc == nil || acc.KeyID != kid || v.key().KeyID() != kid || v.p.Status().State != StatePaired {
		t.Fatal("pairing not kept across a restart")
	}
}

func TestEveryPairingUsesANewKey(t *testing.T) {
	v := newEnv(t)
	k0, err := v.ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	v.start()
	k1 := v.key()
	if k1.KeyID() == k0.KeyID() {
		t.Fatal("existing key reused")
	}
	if _, err := k0.Sign(nil, []byte("m"), crypto.Hash(0)); !errors.Is(err, identity.ErrDestroyed) {
		t.Fatal("old key not destroyed")
	}
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	v.start()
	k2 := v.key()
	if k2.KeyID() == k1.KeyID() {
		t.Fatal("restart reused the key")
	}
	if kids := v.fake.keyIDs(PathCancel); len(kids) != 1 || kids[0] != k1.KeyID() {
		t.Fatalf("first code not cancelled with its key: %v", kids)
	}
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	if v.st.State().Account.KeyID != k2.KeyID() {
		t.Fatal("paired with the wrong key")
	}
}

// After an unpair, pairing again uses a new key, so the server never sees
// a key it registered before and the apps register on the new server.
func TestPairAgainAfterUnpair(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	first := v.st.State().Account
	if err := v.st.Update(func(st *store.State) error {
		st.Targets = append(st.Targets, store.Target{LocalID: jellyfinID, Name: "jellyfin", Host: "127.0.0.1", Port: 8096, Source: store.SourceLocal, ServerServiceID: "11111111-1111-4111-8111-111111111111", Subdomain: "jf"})
		st.Account = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v.wait("unpaired", v.state(StateIdle))
	v.start()
	v.fake.approve()
	v.wait("paired again", v.state(StatePaired))
	second := v.st.State()
	if second.Account.KeyID == first.KeyID || second.Account.ServerID == first.ServerID || second.Account.KeyID != v.key().KeyID() {
		t.Fatal("pairing again kept the old identity")
	}
	if tg := second.Targets[0]; tg.ServerServiceID != "" || tg.Subdomain != "" || tg.Name != "jellyfin" {
		t.Fatalf("app registration kept: %+v", tg)
	}
}

// A 1.x install that was unpaired keeps its token in local state; pairing
// clears it and the enrolment record, and keeps the apps.
func TestPairAfterImportedAccountRemoved(t *testing.T) {
	dir := t.TempDir()
	writeV1(t, dir, "https://api.seawise.io")
	v := newEnvDir(t, dir)
	if _, err := v.p.Start(context.Background(), "nas"); !errors.Is(err, ErrPaired) {
		t.Fatalf("imported account: %v", err)
	}
	if n := v.fake.count(PathRequest); n != 0 {
		t.Fatal("request sent while paired")
	}
	if _, err := v.ks.Current(); !errors.Is(err, identity.ErrNoKey) {
		t.Fatal("key made while paired")
	}
	if tg := v.st.State().Targets[0]; tg.ServerServiceID == "" || tg.Subdomain == "" {
		t.Fatalf("import lost the registration: %+v", tg)
	}
	now := time.Now()
	if err := v.st.Update(func(st *store.State) error {
		st.Enrolment = &store.Enrolment{ServerID: v1Server, Phase: store.PhasePending, StartedAt: now, Hold: store.HoldBadKey, HoldAt: &now}
		st.Account = nil
		st.Targets[0].ServerPublic = true
		st.Targets[0].ServerDisableRequestedAt = &now
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	v.start()
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	st := v.st.State()
	if st.Enrolment != nil || v.st.Secrets().FRPToken != "" || st.Import == nil || st.Import.ServerID != v1Server {
		t.Fatalf("enrolment %+v import %+v", st.Enrolment, st.Import)
	}
	tg := st.Targets[0]
	if tg.ServerServiceID != "" || tg.Subdomain != "" || tg.ServerPublic || tg.ServerDisableRequestedAt != nil || tg.Name != "jellyfin" || tg.Host != "127.0.0.1" {
		t.Fatalf("target %+v", tg)
	}
	v.noSecrets()
}

func TestStartChecks(t *testing.T) {
	v := newEnv(t)
	k0, _ := v.ks.Create()
	for _, name := range []string{strings.Repeat("x", 101), "a\nb", "a\x00", "\xff"} {
		if _, err := v.p.Start(context.Background(), name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", name, err)
		}
	}
	v.origin = "http://api.seawise.io"
	_, err := v.p.Start(context.Background(), "nas")
	var e *Error
	if !errors.As(err, &e) || !strings.Contains(e.Text, "https") {
		t.Fatalf("insecure origin: %v", err)
	}
	if s := v.p.Status(); s.State != StateFailed || s.Error != e.Text {
		t.Fatalf("status %+v", s)
	}
	if v.fake.count(PathRequest) != 0 || v.key().KeyID() != k0.KeyID() {
		t.Fatal("request sent or key replaced")
	}
}

func TestDefaultName(t *testing.T) {
	v := newEnv(t)
	if _, err := v.p.Start(context.Background(), "  "); err != nil {
		t.Fatal(err)
	}
	v.fake.with(func(f *fakePairing) {
		if f.last().name != defaultName {
			t.Fatalf("name %q", f.last().name)
		}
	})
}

func TestRequestRefusals(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{429, `{"error":"Too many requests"}`, "Too many"},
		{503, `{"error":"Pairing is paused"}`, "paused"},
		{400, `{"error":"invalid_key","code":"bad_key"}`, "device key"},
		{400, `{"error":"Validation failed"}`, "server name"},
		{401, `{"error":"invalid_proof","code":"replayed"}`, "(replayed)"},
		{401, `{"error":"invalid_proof","code":"Bad Code"}`, "(unknown)"},
		{418, `{}`, "status 418"},
	}
	for _, c := range cases {
		v := newEnv(t)
		v.fake.with(func(f *fakePairing) { f.script[PathRequest] = []scripted{{status: c.status, body: c.body}} })
		_, err := v.p.Start(context.Background(), "nas")
		var e *Error
		if !errors.As(err, &e) || !strings.Contains(e.Text, c.want) {
			t.Errorf("%d %s: %v", c.status, c.body, err)
			continue
		}
		if s := v.p.Status(); s.State != StateFailed || s.Error != e.Text || s.Code != "" {
			t.Errorf("%d: status %+v", c.status, s)
		}
	}
}

func TestRequestUnreachable(t *testing.T) {
	v := newEnv(t)
	v.srv.Close()
	_, err := v.p.Start(context.Background(), "nas")
	var e *Error
	if !errors.As(err, &e) || !strings.Contains(e.Text, "Could not reach") {
		t.Fatal(err)
	}
}

func TestRequestBadAnswers(t *testing.T) {
	cases := map[string]func(map[string]any){
		"other key":      func(d map[string]any) { d["key_id"] = strings.Repeat("A", 43) },
		"lower code":     func(d map[string]any) { d["user_code"] = "abcdefghjk" },
		"short code":     func(d map[string]any) { d["user_code"] = "ABCDEFGHJ" },
		"confusable":     func(d map[string]any) { d["user_code"] = "ABCDEFGHJ0" },
		"device code":    func(d map[string]any) { d["device_code"] = strings.Repeat("G", 32) },
		"expired":        func(d map[string]any) { d["expires_at"] = "2001-01-01T00:00:00Z" },
		"bad time":       func(d map[string]any) { d["expires_at"] = "soon" },
		"extra member":   func(d map[string]any) { d["frp_token"] = "x" },
		"no key":         func(d map[string]any) { delete(d, "key_id") },
		"number code":    func(d map[string]any) { d["user_code"] = 5 },
		"null poll":      func(d map[string]any) { d["poll_url"] = nil },
		"missing device": func(d map[string]any) { delete(d, "device_code") },
	}
	for name, fn := range cases {
		v := newEnv(t)
		v.fake.with(func(f *fakePairing) { f.answer[PathRequest] = fn })
		_, err := v.p.Start(context.Background(), "nas")
		if name == "null poll" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || v.p.Status().State != StateFailed {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCodeLifeIsCapped(t *testing.T) {
	v := newEnv(t)
	v.fake.with(func(f *fakePairing) {
		f.answer[PathRequest] = func(d map[string]any) { d["expires_at"] = v.clk.now().Add(48 * time.Hour).UTC().Format(time.RFC3339) }
	})
	s := v.start()
	if s.ExpiresAt.After(v.clk.now().Add(maxCodeLife)) {
		t.Fatalf("expiry %v", s.ExpiresAt)
	}
}

func TestPollEndings(t *testing.T) {
	for status, want := range map[string]string{"expired": "expired", "cancelled": "cancelled", "invalid": "no longer knows"} {
		v := newEnv(t)
		v.start()
		v.fake.setStatus(status)
		v.wait(status, v.state(StateFailed))
		if s := v.p.Status(); !strings.Contains(s.Error, want) || s.Code != "" {
			t.Errorf("%s: %+v", status, s)
		}
		if v.st.State().Account != nil {
			t.Fatal("paired")
		}
		n := v.fake.count(PathStatus)
		time.Sleep(20 * time.Millisecond)
		if v.fake.count(PathStatus) != n {
			t.Fatal("still polling")
		}
		v.p.Cancel()
		if v.fake.count(PathCancel) != 0 {
			t.Fatal("cancel sent for an ended code")
		}
	}
}

func TestPollKeepsWaitingOnTransientAnswers(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.with(func(f *fakePairing) {
		f.script[PathStatus] = []scripted{
			{status: 503}, {status: 500}, {status: 404}, {status: 401, body: `{"error":"invalid_proof","code":"replayed"}`},
			{status: 429, header: map[string]string{"Retry-After": "0"}}, {status: 200, body: `{"data":{"status":"later"}}`},
			{status: 200, body: `{"status":"pending"}`},
		}
	})
	v.wait("transient answers", func() bool { return v.fake.count(PathStatus) >= 9 })
	if v.p.Status().State != StatePending {
		t.Fatalf("status %+v", v.p.Status())
	}
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
}

func TestPollNotesProblems(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.with(func(f *fakePairing) {
		f.script[PathStatus] = []scripted{{status: 503}, {status: 503}, {status: 503}, {status: 503}, {status: 503}, {status: 503}, {status: 503}, {status: 503}}
	})
	v.wait("problem shown", func() bool { return strings.Contains(v.p.Status().Error, "503") })
	v.wait("cleared", func() bool { return v.p.Status().Error == "" })
}

func TestPollRefusalEnds(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.with(func(f *fakePairing) { f.script[PathStatus] = []scripted{{status: 418}} })
	v.wait("refused", v.state(StateFailed))
	if !strings.Contains(v.p.Status().Error, "418") {
		t.Fatal(v.p.Status())
	}
}

func TestRetryAfterSlowsPolling(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.with(func(f *fakePairing) {
		f.script[PathStatus] = []scripted{{status: 429, header: map[string]string{"Retry-After": "3600"}}}
	})
	v.wait("limited", func() bool { return v.fake.count(PathStatus) >= 1 })
	time.Sleep(30 * time.Millisecond)
	if n := v.fake.count(PathStatus); n != 1 {
		t.Fatalf("%d polls inside Retry-After", n)
	}
	if !strings.Contains(v.p.Status().Error, "rate limited") {
		t.Fatal(v.p.Status())
	}
}

func TestCompleteRefusals(t *testing.T) {
	cases := map[int]string{400: "not approved", 403: "server limit", 409: "status 409"}
	for status, want := range cases {
		v := newEnv(t)
		v.start()
		v.fake.with(func(f *fakePairing) { f.script[PathComplete] = []scripted{{status: status}} })
		v.fake.approve()
		v.wait("refused", v.state(StateFailed))
		if !strings.Contains(v.p.Status().Error, want) || v.st.State().Account != nil {
			t.Errorf("%d: %+v", status, v.p.Status())
		}
	}
}

func TestCompleteRetriedAfterOutage(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.with(func(f *fakePairing) {
		f.script[PathComplete] = []scripted{{status: 503}, {status: 401, body: `{"error":"use_dpop_nonce"}`}, {status: 200, body: `{"data":{}}`}}
	})
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	if n := v.fake.count(PathComplete); n != 4 {
		t.Fatalf("%d completions", n)
	}
}

// A completion whose answer is lost shows as used; completing again with
// the same key returns the same pairing.
func TestLostCompletionAnswer(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.fake.with(func(f *fakePairing) { f.lose[PathComplete] = 1 })
	v.fake.approve()
	v.wait("paired", v.state(StatePaired))
	v.fake.with(func(f *fakePairing) {
		if f.last().status != "completed" || f.calls[PathComplete] != 2 {
			t.Fatalf("%+v %d", f.last(), f.calls[PathComplete])
		}
		if v.st.State().Account.ServerID != f.last().serverID {
			t.Fatal("other server stored")
		}
	})
}

func TestCompleteBadAnswers(t *testing.T) {
	cases := map[string]func(map[string]any){
		"other key":   func(d map[string]any) { d["key_id"] = strings.Repeat("A", 43) },
		"bad server":  func(d map[string]any) { d["server_id"] = "x" },
		"bad device":  func(d map[string]any) { d["device_id"] = "" },
		"bad user":    func(d map[string]any) { d["user_id"] = "u1" },
		"frp token":   func(d map[string]any) { d["frp_token"] = v1Token },
		"user email":  func(d map[string]any) { d["user_email"] = "a@b" },
		"bad name ok": func(d map[string]any) { d["server_name"] = "a\x01" },
		"null name":   func(d map[string]any) { d["server_name"] = nil },
	}
	for name, fn := range cases {
		v := newEnv(t)
		v.start()
		v.fake.with(func(f *fakePairing) { f.answer[PathComplete] = fn })
		v.fake.approve()
		switch name {
		case "other key":
			v.wait(name, v.state(StateFailed))
			if v.st.State().Account != nil {
				t.Fatal("paired with another key")
			}
		case "bad name ok", "null name":
			v.wait(name, v.state(StatePaired))
			if v.st.State().Account.ServerName != "" {
				t.Fatalf("%s: name %q", name, v.st.State().Account.ServerName)
			}
		default:
			v.wait(name, func() bool { return v.fake.count(PathComplete) >= 3 })
			if v.st.State().Account != nil || v.p.Status().State != StatePending || !strings.Contains(v.p.Status().Error, "unexpected") {
				t.Fatalf("%s accepted: %+v", name, v.p.Status())
			}
		}
	}
}

func TestPairedMeanwhile(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	other := &store.Account{ServerID: "00000000-0000-4000-8000-0000000000ff", DeviceID: "d0000000-0000-4000-8000-0000000000ff", KeyID: strings.Repeat("B", 43)}
	if err := v.st.Update(func(st *store.State) error { st.Account = other; return nil }); err != nil {
		t.Fatal(err)
	}
	v.fake.approve()
	v.wait("completed", func() bool { return v.fake.count(PathComplete) >= 1 })
	v.wait("ended", func() bool {
		v.p.mu.Lock()
		defer v.p.mu.Unlock()
		return v.p.cur == nil
	})
	v.p.mu.Lock()
	s := v.p.status
	v.p.mu.Unlock()
	if s.State != StateFailed || v.st.State().Account.ServerID != other.ServerID {
		t.Fatalf("status %+v", s)
	}
}

func TestCodeExpiresLocally(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	v.clk.add(16 * time.Minute)
	v.wait("expired", v.state(StateFailed))
	if !strings.Contains(v.p.Status().Error, "expired") {
		t.Fatal(v.p.Status())
	}
}

func TestCancel(t *testing.T) {
	v := newEnv(t)
	v.start()
	k := v.key()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	v.p.Cancel()
	if s := v.p.Status(); s.State != StateIdle || s.Code != "" {
		t.Fatalf("status %+v", s)
	}
	if kids := v.fake.keyIDs(PathCancel); len(kids) != 1 || kids[0] != k.KeyID() {
		t.Fatalf("cancel %v", kids)
	}
	if !strings.Contains(v.logs.String(), "pairing cancelled") || strings.Contains(v.logs.String(), "not sent") {
		t.Fatal("cancel not logged")
	}
	v.fake.with(func(f *fakePairing) {
		if f.last().status != "cancelled" {
			t.Fatal("code not cancelled")
		}
	})
	n := v.fake.count(PathStatus)
	time.Sleep(20 * time.Millisecond)
	if v.fake.count(PathStatus) != n {
		t.Fatal("still polling")
	}
	v.p.Cancel()
	if v.fake.count(PathCancel) != 1 {
		t.Fatal("second cancel sent")
	}
}

func TestCancelUnreachableStillStops(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	v.srv.CloseClientConnections()
	v.srv.Close()
	v.p.Cancel()
	if v.p.Status().State != StateIdle || !strings.Contains(v.logs.String(), "pairing cancel not sent") || strings.Contains(v.logs.String(), "pairing cancelled") {
		t.Fatal(v.p.Status())
	}
}

func TestStopsWithAgent(t *testing.T) {
	v := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	v.p.cfg.Context = ctx
	v.start()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	cancel()
	time.Sleep(20 * time.Millisecond)
	n := v.fake.count(PathStatus)
	time.Sleep(20 * time.Millisecond)
	if v.fake.count(PathStatus) != n {
		t.Fatal("polling after the agent stopped")
	}
}

func TestNewChecksConfig(t *testing.T) {
	v := newEnv(t)
	call, _ := devicecall.New(devicecall.Config{})
	origin := func() string { return "" }
	for i, c := range []Config{
		{Keys: v.ks, Caller: call, Origin: origin},
		{Store: v.st, Caller: call, Origin: origin},
		{Store: v.st, Keys: v.ks, Origin: origin},
		{Store: v.st, Keys: v.ks, Caller: call},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
	p, err := New(Config{Store: v.st, Keys: v.ks, Caller: call, Origin: origin})
	if err != nil || p.cfg.Poll != defaultPoll || p.cfg.Context == nil || p.cfg.Now == nil || p.cfg.Logger == nil || p.Status().State != StateIdle {
		t.Fatal("defaults")
	}
}

func TestKeystoreFailure(t *testing.T) {
	v := newEnv(t)
	v.ks.Close()
	_, err := v.p.Start(context.Background(), "nas")
	var e *Error
	if !errors.As(err, &e) || !strings.Contains(e.Text, "device key") || v.fake.count(PathRequest) != 0 {
		t.Fatal(err)
	}
	v.ks = nil
}

func TestApproveURL(t *testing.T) {
	cases := map[string]string{
		"https://seawise.io":     "https://seawise.io/connect",
		"https://seawise.io/":    "https://seawise.io/connect",
		"http://localhost:3000":  "http://localhost:3000/connect",
		"":                       "",
		"ftp://seawise.io":       "",
		"https://seawise.io/x":   "",
		"https://u@seawise.io":   "",
		"https://seawise.io?q=1": "",
		"https://seawise.io#f":   "",
		"javascript:alert(1)":    "",
		"%":                      "",
		"https:///no-host":       "",
	}
	for in, want := range cases {
		if got := approveURL(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestSaveFailureIsRetried(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	dir := t.TempDir()
	writeV1(t, dir, "https://api.seawise.io")
	v := newEnvDir(t, dir)
	if err := v.st.Update(func(st *store.State) error { st.Account = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	v.start()
	if err := os.Chmod(v.st.Dir(), 0o500); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			_ = os.Chmod(v.st.Dir(), 0o700)
		}
	}
	t.Cleanup(restore)
	v.fake.approve()
	v.wait("save failure shown", func() bool { return strings.Contains(v.p.Status().Error, "could not save the pairing") })
	if v.st.State().Account != nil || v.st.Secrets().FRPToken == "" {
		t.Fatal("state changed")
	}
	restore()
	v.wait("paired", v.state(StatePaired))
	if v.st.Secrets().FRPToken != "" || !v.st.State().Account.Keyed() {
		t.Fatal("token kept")
	}
}
