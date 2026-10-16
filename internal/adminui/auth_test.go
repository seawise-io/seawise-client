package adminui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func newAuth(t *testing.T, st *store.Store, clk *testClock) *Auth {
	t.Helper()
	a, err := NewAuth(AuthConfig{Store: st, Now: clk.Now, BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const goodPassword = "correct horse battery"

func TestSetupWithinWindow(t *testing.T) {
	st := newStore(t, nil)
	clk := &testClock{now: t0}
	a := newAuth(t, st, clk)
	if !a.SetupRequired() || a.SetupClosed() {
		t.Fatal("fresh install not in setup")
	}
	clk.now = t0.Add(constants.FirstRunSetupWindow - time.Second)
	if err := a.Setup("10.0.0.1", goodPassword); err != nil {
		t.Fatal(err)
	}
	if a.SetupRequired() || a.SetupClosed() || st.Secrets().AdminPasswordHash == "" {
		t.Fatal("setup not recorded")
	}
	if bcrypt.CompareHashAndPassword([]byte(st.Secrets().AdminPasswordHash), []byte(goodPassword)) != nil {
		t.Fatal("hash does not match")
	}
}

func TestSetupClosedAfterWindow(t *testing.T) {
	st := newStore(t, nil)
	clk := &testClock{now: t0}
	a := newAuth(t, st, clk)
	clk.now = t0.Add(constants.FirstRunSetupWindow)
	if !a.SetupClosed() {
		t.Fatal("window still open")
	}
	if err := a.Setup("127.0.0.1", goodPassword); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("setup after the window: %v", err)
	}
	if st.Secrets().AdminPasswordHash != "" || !a.SetupRequired() {
		t.Fatal("password set after the window")
	}
	clk.now = clk.now.Add(time.Hour)
	if err := a.Setup("127.0.0.1", goodPassword); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("window reopened without a restart: %v", err)
	}
	// A restart opens a new window.
	b := newAuth(t, st, clk)
	if b.SetupClosed() {
		t.Fatal("restart did not reopen the window")
	}
	if err := b.Setup("127.0.0.1", goodPassword); err != nil {
		t.Fatal(err)
	}
}

func TestSetupValidatesPassword(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0})
	for _, pw := range []string{"", "short", strings.Repeat("x", 73)} {
		if err := a.Setup("10.0.0.1", pw); !errors.Is(err, ErrBadPassword) {
			t.Fatalf("%q: %v", pw, err)
		}
	}
	if !a.SetupRequired() {
		t.Fatal("setup ended without success")
	}
}

func ipN(i int) string { return "10.1." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250+1) }

func TestSetupRateLimitPerIP(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0})
	for i := 0; i < setupMaxFailsPerIP; i++ {
		_ = a.Setup("10.0.0.9", "short")
	}
	if err := a.Setup("10.0.0.9", goodPassword); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("address not limited: %v", err)
	}
	// Another address on the LAN is not locked out by the first.
	if err := a.Setup("10.0.0.10", goodPassword); err != nil {
		t.Fatalf("other address blocked: %v", err)
	}
}

func TestSetupRateLimitExpires(t *testing.T) {
	clk := &testClock{now: t0}
	a := newAuth(t, newStore(t, nil), clk)
	for i := 0; i < setupMaxFailsPerIP; i++ {
		_ = a.Setup("10.0.0.9", "short")
	}
	clk.now = clk.now.Add(time.Minute)
	if err := a.Setup("10.0.0.9", goodPassword); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("address not limited: %v", err)
	}
}

func TestSetupGlobalBudgetSparesLoopback(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0})
	for i := 0; i < setupMaxFailsGlobal; i++ {
		_ = a.Setup(ipN(i), "short")
	}
	if err := a.Setup("10.9.9.9", goodPassword); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("global budget not enforced: %v", err)
	}
	if err := a.Setup("127.0.0.1", goodPassword); err != nil {
		t.Fatalf("loopback locked out: %v", err)
	}
}

func TestSetupOnce(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, done := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := a.Setup("10.0.0.1", goodPassword)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrSetupDone):
				done++
			}
		}()
	}
	wg.Wait()
	if ok != 1 || done != 7 {
		t.Fatalf("ok %d done %d", ok, done)
	}
}

func TestEqualSecretLengthIndependent(t *testing.T) {
	// equalSecret hashes both sides, so inputs of any length are compared
	// as 32-byte digests.
	if equalSecret("a", "ab") || !equalSecret("same", "same") || equalSecret("", "x") {
		t.Fatal("equalSecret")
	}
}

func TestExistingPasswordNoSetup(t *testing.T) {
	st := newStore(t, nil)
	hash, _ := bcrypt.GenerateFromPassword([]byte("old password!"), bcrypt.MinCost)
	st.UpdateSecrets(func(s *store.Secrets) error { s.AdminPasswordHash = string(hash); return nil })
	clk := &testClock{now: t0}
	a := newAuth(t, st, clk)
	if a.SetupRequired() || a.SetupClosed() {
		t.Fatal("setup state with a password")
	}
	if err := a.Setup("127.0.0.1", goodPassword); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("setup inside the window replaced the password: %v", err)
	}
	clk.now = t0.Add(constants.FirstRunSetupWindow + time.Hour)
	if a.SetupClosed() {
		t.Fatal("closed window reported with a password")
	}
	if err := a.Setup("127.0.0.1", goodPassword); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("setup after the window: %v", err)
	}
	if st.Secrets().AdminPasswordHash != string(hash) {
		t.Fatal("password changed")
	}
	if _, err := a.Login("10.0.0.1", "old password!"); err != nil {
		t.Fatal(err)
	}
}

func TestLoginRateLimit(t *testing.T) {
	st := newStore(t, nil)
	clk := &testClock{now: t0}
	a := newAuth(t, st, clk)
	if _, err := a.Login("10.0.0.1", "x"); !errors.Is(err, ErrSetupPending) {
		t.Fatalf("login in setup mode: %v", err)
	}
	a.Setup("10.0.0.1", goodPassword)
	if _, err := a.Login("10.0.0.1", "wrong"); !errors.Is(err, ErrWrongLogin) {
		t.Fatal(err)
	}
	if wait, err := a.Login("10.0.0.1", "correct horse battery"); !errors.Is(err, ErrRateLimited) || wait <= 0 {
		t.Fatalf("no backoff: %v", err)
	}
	if _, err := a.Login("10.0.0.2", "correct horse battery"); err != nil {
		t.Fatalf("other address blocked: %v", err)
	}
	clk.now = clk.now.Add(loginMaxDelay)
	if _, err := a.Login("10.0.0.1", "correct horse battery"); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
}

func TestLoginGlobalBudgetSparesLoopback(t *testing.T) {
	clk := &testClock{now: t0}
	a := newAuth(t, newStore(t, nil), clk)
	a.Setup("10.0.0.1", goodPassword)
	for i := 0; i < loginGlobalMax; i++ {
		a.Login(ipN(i), "wrong")
	}
	if _, err := a.Login("10.9.9.9", "correct horse battery"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("global budget: %v", err)
	}
	if _, err := a.Login("127.0.0.1", "correct horse battery"); err != nil {
		t.Fatalf("owner on loopback locked out: %v", err)
	}
	clk.now = clk.now.Add(loginGlobalWindow)
	if _, err := a.Login("10.9.9.9", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
}

func TestLoginReservesBeforeCompare(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0})
	a.Setup("10.0.0.1", goodPassword)
	var inFlight, peak atomic.Int32
	a.compare = func(h, p []byte) error {
		n := inFlight.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return bcrypt.ErrMismatchedHashAndPassword
	}
	var wg sync.WaitGroup
	var wrong atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Login("10.0.0.5", "guess"); errors.Is(err, ErrWrongLogin) {
				wrong.Add(1)
			}
		}()
	}
	wg.Wait()
	if wrong.Load() != 1 {
		t.Fatalf("%d guesses from one address reached the password check", wrong.Load())
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); a.Login(ipN(i), "guess") }(i)
	}
	wg.Wait()
	if peak.Load() > maxConcurrentHash {
		t.Fatalf("%d concurrent password checks", peak.Load())
	}
}

func TestBindAddr(t *testing.T) {
	up := t0
	for _, c := range []struct {
		explicit   string
		upgraded   *time.Time
		hash       string
		container  bool
		want       string
		wantNotice bool
	}{
		{"10.0.0.5", &up, "h", false, "10.0.0.5", false},
		{"", &up, "h", false, "127.0.0.1", true},
		{"", &up, "h", true, "0.0.0.0", false},
		{"", &up, "", false, "127.0.0.1", false},
		{"", nil, "h", false, "127.0.0.1", false},
		{"", nil, "", true, "0.0.0.0", false},
		{"", nil, "", false, "127.0.0.1", false},
	} {
		got, notice := BindAddr(c.explicit, store.State{UpgradedAt: c.upgraded}, store.Secrets{AdminPasswordHash: c.hash}, c.container)
		if got != c.want || (notice != "") != c.wantNotice {
			t.Errorf("%+v: %s %q", c, got, notice)
		}
		if notice != "" && !strings.Contains(notice, "SEAWISE_BIND_ADDR") {
			t.Errorf("notice does not say how to expose the UI: %q", notice)
		}
	}
}

func TestDetectContainer(t *testing.T) {
	root := t.TempDir()
	if detectContainer(root, func(string) string { return "" }) {
		t.Fatal("empty root detected as container")
	}
	if !detectContainer(root, func(k string) string {
		if k == "SEAWISE_CONTAINER" {
			return "1"
		}
		return ""
	}) {
		t.Fatal("env flag ignored")
	}
	os.MkdirAll(filepath.Join(root, "proc/1"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/1/cgroup"), []byte("0::/init.scope\n"), 0o644)
	if detectContainer(root, func(string) string { return "" }) {
		t.Fatal("host cgroup detected as container")
	}
	for _, cg := range []string{"12:pids:/docker/abc\n", "0::/kubepods/besteffort/pod1\n", "0::/system.slice/containerd.service\n", "1:name=systemd:/libpod_parent/x\n", "0::/lxc.payload.c1\n"} {
		os.WriteFile(filepath.Join(root, "proc/1/cgroup"), []byte(cg), 0o644)
		if !detectContainer(root, func(string) string { return "" }) {
			t.Errorf("cgroup %q not detected", cg)
		}
	}
	os.WriteFile(filepath.Join(root, "proc/1/cgroup"), []byte("0::/\n"), 0o644)
	os.WriteFile(filepath.Join(root, ".dockerenv"), nil, 0o644)
	if !detectContainer(root, func(string) string { return "" }) {
		t.Fatal(".dockerenv not detected")
	}
}

func post(s *Server, path, body, host string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = host
	r.RemoteAddr = "192.168.1.50:40000"
	r.Header.Set("Origin", "https://"+host)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.SecureHandler().ServeHTTP(w, r)
	return w
}

func TestSetupAndLoginOverHTTP(t *testing.T) {
	st := newStore(t, nil)
	s := newServer(t, st, &testClock{now: t0})
	const host = "192.168.1.10:8082"
	if w := post(s, "/api/auth/login", `{"password":"x"}`, host, nil); w.Code != http.StatusConflict {
		t.Fatalf("login before setup %d", w.Code)
	}
	if w := post(s, "/api/setup", `{"password":"short"}`, host, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("short password %d", w.Code)
	}
	if w := post(s, "/api/setup", `{"code":"x","password":"correct horse battery"}`, host, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field %d", w.Code)
	}
	body := `{"password":"correct horse battery"}`
	w := post(s, "/api/setup", body, host, nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != SessionCookie {
		t.Fatalf("setup %d %v", w.Code, w.Result().Cookies())
	}
	if w := post(s, "/api/setup", body, host, nil); w.Code != http.StatusConflict {
		t.Fatalf("second setup %d", w.Code)
	}
	if w := post(s, "/api/auth/login", `{"password":"nope nope nope"}`, host, nil); w.Code != 401 {
		t.Fatalf("wrong login %d", w.Code)
	}
	if w := post(s, "/api/auth/login", `{"password":"correct horse battery"}`, host, nil); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("backoff %d", w.Code)
	}
	// Login without a same-origin Origin is refused before any check.
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"password":"correct horse battery"}`))
	r.Host = host
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.SecureHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("cross-site login %d", w.Code)
	}
}

func authStatus(t *testing.T, s *Server, host string) map[string]any {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/auth/status", nil)
	r.Host = host
	r.RemoteAddr = "192.168.1.50:40000"
	w := httptest.NewRecorder()
	s.SecureHandler().ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	return out
}

func TestSetupWindowOverHTTP(t *testing.T) {
	clk := &testClock{now: t0}
	s := newServer(t, newStore(t, nil), clk)
	const host = "192.168.1.10:8082"
	if st := authStatus(t, s, host); st["setup_required"] != true || st["setup_timed_out"] != false {
		t.Fatalf("status inside the window %v", st)
	}
	clk.now = t0.Add(constants.FirstRunSetupWindow + time.Second)
	if st := authStatus(t, s, host); st["setup_required"] != true || st["setup_timed_out"] != true {
		t.Fatalf("status after the window %v", st)
	}
	w := post(s, "/api/setup", `{"password":"correct horse battery"}`, host, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Setup timed out for security. Restart the client to set a password.") {
		t.Fatalf("setup after the window %d %s", w.Code, w.Body.String())
	}
}

func TestLANFloodCannotBlockLoopbackLogin(t *testing.T) {
	clk := &testClock{now: t0}
	a := newAuth(t, newStore(t, nil), clk)
	a.Setup("127.0.0.1", goodPassword)
	// Fill the per-address table and the global budget from the LAN.
	for i := 0; i < maxTrackedIPs+10; i++ {
		if i%90 == 0 {
			clk.now = clk.now.Add(loginGlobalWindow)
		}
		a.Login(ipN(i), "wrong")
	}
	for i := 0; i < loginLocalMax-1; i++ {
		a.Login("127.0.0."+strconv.Itoa(i%250+2), "wrong")
		clk.now = clk.now.Add(loginMaxDelay)
	}
	if _, err := a.Login("127.0.0.1", "correct horse battery"); err != nil {
		t.Fatalf("owner on loopback locked out by a LAN flood: %v", err)
	}
}

func TestIPv6KeyedBySlash64(t *testing.T) {
	clk := &testClock{now: t0}
	a := newAuth(t, newStore(t, nil), clk)
	for i := 0; i < setupMaxFailsPerIP; i++ {
		_ = a.Setup("2001:db8:1:2::"+strconv.Itoa(i+1), "short")
	}
	if err := a.Setup("2001:db8:1:2::ffff", goodPassword); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rotating within a /64 escaped the per-address limit: %v", err)
	}
	if err := a.Setup("2001:db8:1:3::1", goodPassword); err != nil {
		t.Fatalf("other /64 blocked: %v", err)
	}
	a.Login("2001:db8:9:9::1", "wrong")
	if _, err := a.Login("2001:db8:9:9::2", "correct horse battery"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("login backoff not shared within a /64: %v", err)
	}
}
