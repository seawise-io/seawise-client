package adminui

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func newAuth(t *testing.T, st *store.Store, clk *testClock, pwFile string) *Auth {
	t.Helper()
	a, err := NewAuth(AuthConfig{Store: st, Now: clk.Now, BcryptCost: bcrypt.MinCost, PasswordFile: pwFile})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func codeFromFile(t *testing.T, a *Auth) string {
	t.Helper()
	b, err := os.ReadFile(a.CodePath())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestSetupCodeFile(t *testing.T) {
	st := newStore(t, nil)
	a := newAuth(t, st, &testClock{now: t0}, "")
	code := a.SetupCode()
	if !regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){4}$`).MatchString(code) {
		t.Fatalf("code %q", code)
	}
	fi, err := os.Stat(a.CodePath())
	if err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(a.CodePath()) != st.Dir() {
		t.Fatalf("code file %v %v", fi, err)
	}
	if codeFromFile(t, a) != code {
		t.Fatal("file and log code differ")
	}
	if err := a.Setup(strings.ToLower(strings.ReplaceAll(code, "-", " ")), "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.CodePath()); !os.IsNotExist(err) {
		t.Fatal("code file kept after setup")
	}
	if a.SetupRequired() || a.SetupCode() != "" || st.Secrets().AdminPasswordHash == "" {
		t.Fatal("setup not recorded")
	}
	if bcrypt.CompareHashAndPassword([]byte(st.Secrets().AdminPasswordHash), []byte("correct horse battery")) != nil {
		t.Fatal("hash does not match")
	}
}

func TestNewCodeEveryStart(t *testing.T) {
	st := newStore(t, nil)
	a := newAuth(t, st, &testClock{now: t0}, "")
	b := newAuth(t, st, &testClock{now: t0}, "")
	if a.SetupCode() == b.SetupCode() || codeFromFile(t, b) != b.SetupCode() {
		t.Fatal("code reused across starts")
	}
}

func TestSetupRequiresCode(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0}, "")
	for _, c := range []string{"", "AAAA-AAAA-AAAA-AAAA-AAAA", a.SetupCode() + "A", a.SetupCode()[:20]} {
		if err := a.Setup(c, "correct horse battery"); !errors.Is(err, ErrSetupCode) {
			t.Fatalf("code %q: %v", c, err)
		}
	}
	if err := a.Setup(a.SetupCode(), "short"); !errors.Is(err, ErrBadPassword) {
		t.Fatal(err)
	}
	if err := a.Setup(a.SetupCode(), strings.Repeat("x", 73)); !errors.Is(err, ErrBadPassword) {
		t.Fatal(err)
	}
	if !a.SetupRequired() {
		t.Fatal("setup ended without success")
	}
}

func TestSetupRateLimit(t *testing.T) {
	clk := &testClock{now: t0}
	a := newAuth(t, newStore(t, nil), clk, "")
	code := a.SetupCode()
	for i := 0; i < setupMaxFails; i++ {
		_ = a.Setup("WRONG", "correct horse battery")
	}
	if err := a.Setup(code, "correct horse battery"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("not limited: %v", err)
	}
	clk.now = clk.now.Add(setupWindow)
	if err := a.Setup(code, "correct horse battery"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestSetupRotates(t *testing.T) {
	clk := &testClock{now: t0}
	a := newAuth(t, newStore(t, nil), clk, "")
	first := a.SetupCode()
	for i := 0; i < setupRotateAfter; i++ {
		if i%setupMaxFails == 0 {
			clk.now = clk.now.Add(setupWindow)
		}
		_ = a.Setup("WRONG", "correct horse battery")
	}
	if a.SetupCode() == first || codeFromFile(t, a) != a.SetupCode() {
		t.Fatal("code not rotated")
	}
	clk.now = clk.now.Add(setupWindow)
	if err := a.Setup(first, "correct horse battery"); !errors.Is(err, ErrSetupCode) {
		t.Fatalf("old code still valid: %v", err)
	}
}

func TestSetupOnce(t *testing.T) {
	a := newAuth(t, newStore(t, nil), &testClock{now: t0}, "")
	code := a.SetupCode()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, done := 0, 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := a.Setup(code, "correct horse battery")
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

func TestSetupCodeCompareLengthIndependent(t *testing.T) {
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
	os.WriteFile(filepath.Join(st.Dir(), SetupCodeFile), []byte("STALE"), 0o600)
	a := newAuth(t, st, &testClock{now: t0}, "")
	if a.SetupRequired() {
		t.Fatal("setup required with a password")
	}
	if _, err := os.Stat(a.CodePath()); !os.IsNotExist(err) {
		t.Fatal("stale code file kept")
	}
	if _, err := a.Login("10.0.0.1", "old password!"); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordFile(t *testing.T) {
	st := newStore(t, nil)
	pf := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pf, []byte("from the file 123\n"), 0o600)
	a := newAuth(t, st, &testClock{now: t0}, pf)
	if a.SetupRequired() {
		t.Fatal("setup required with password file")
	}
	if _, err := a.Login("10.0.0.1", "from the file 123"); err != nil {
		t.Fatal(err)
	}
	hash := st.Secrets().AdminPasswordHash
	newAuth(t, st, &testClock{now: t0}, pf)
	if st.Secrets().AdminPasswordHash != hash {
		t.Fatal("unchanged file rehashed")
	}
	if err := os.WriteFile(pf, []byte("rotated password\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a = newAuth(t, st, &testClock{now: t0}, pf)
	if _, err := a.Login("10.0.0.2", "rotated password"); err != nil {
		t.Fatal("rotation not applied")
	}
}

func TestPasswordFileErrors(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("short"), 0o400)
	big := filepath.Join(dir, "big")
	os.WriteFile(big, bytes.Repeat([]byte("x"), maxPasswordFile+1), 0o400)
	for _, p := range []string{filepath.Join(dir, "missing"), dir, short, big} {
		if _, err := NewAuth(AuthConfig{Store: newStore(t, nil), BcryptCost: bcrypt.MinCost, PasswordFile: p}); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	st := newStore(t, nil)
	clk := &testClock{now: t0}
	a := newAuth(t, st, clk, "")
	if _, err := a.Login("10.0.0.1", "x"); !errors.Is(err, ErrSetupPending) {
		t.Fatalf("login in setup mode: %v", err)
	}
	a.Setup(a.SetupCode(), "correct horse battery")
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
	for i := 0; i < loginGlobalMax; i++ {
		a.Login("10.1.0."+string(rune('a'+i%26))+string(rune('a'+i/26)), "wrong")
	}
	if _, err := a.Login("10.9.9.9", "correct horse battery"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("global cap: %v", err)
	}
	clk.now = clk.now.Add(loginGlobalWindow)
	if _, err := a.Login("10.9.9.9", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
}

func TestBindAddr(t *testing.T) {
	up := t0
	for _, c := range []struct {
		explicit  string
		upgraded  *time.Time
		hash      string
		container bool
		want      string
	}{
		{"10.0.0.5", nil, "", false, "10.0.0.5"},
		{"", &up, "h", false, "0.0.0.0"},
		{"", &up, "", false, "127.0.0.1"},
		{"", nil, "h", false, "127.0.0.1"},
		{"", nil, "", true, "0.0.0.0"},
		{"", nil, "", false, "127.0.0.1"},
	} {
		got := BindAddr(c.explicit, store.State{UpgradedAt: c.upgraded}, store.Secrets{AdminPasswordHash: c.hash}, c.container)
		if got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
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
	if w := post(s, "/api/setup", `{"code":"WRONG","password":"correct horse battery"}`, host, nil); w.Code != http.StatusForbidden {
		t.Fatalf("wrong code %d", w.Code)
	}
	if w := post(s, "/api/setup", `{"code":"x","password":"y","extra":1}`, host, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field %d", w.Code)
	}
	body, _ := json.Marshal(map[string]string{"code": s.cfg.Auth.SetupCode(), "password": "correct horse battery"})
	w := post(s, "/api/setup", string(body), host, nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != SessionCookie {
		t.Fatalf("setup %d %v", w.Code, w.Result().Cookies())
	}
	if w := post(s, "/api/setup", string(body), host, nil); w.Code != http.StatusConflict {
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
