package adminui

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// v1upgrade opens a store on a copy of a 1.x data folder whose password,
// set by 1.x, is password.
func v1upgrade(t *testing.T, group, password string) *store.Store {
	t.Helper()
	src := filepath.Join("..", "legacy", "testdata", "v1", group)
	dst := t.TempDir()
	if err := os.Chmod(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			return os.Mkdir(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "password.hash"), hash, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dst, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// 1.x allowed 8 characters: an upgraded install keeps signing in with them;
// only a new password must meet the current minimum.
func TestUpgradedShortPasswordSignsIn(t *testing.T) {
	for _, group := range []string{"A", "B", "C", "D", "E"} {
		const old = "v1pass88"
		st := v1upgrade(t, group, old)
		a, err := NewAuth(AuthConfig{Store: st, BcryptCost: bcrypt.MinCost})
		if err != nil {
			t.Fatal(err)
		}
		if a.SetupRequired() {
			t.Fatalf("%s: imported password not used", group)
		}
		if _, err := a.Login("192.168.1.9", old); err != nil {
			t.Fatalf("%s: 8-character 1.x password refused: %v", group, err)
		}
		if _, err := a.ChangePassword("192.168.1.9", old, "short9chr"); !errors.Is(err, ErrBadPassword) {
			t.Fatalf("%s: new 9-byte password: %v", group, err)
		}
		if _, err := a.ChangePassword("192.168.1.9", old, goodPassword); err != nil {
			t.Fatalf("%s: change: %v", group, err)
		}
		if _, err := a.Login("192.168.1.9", old); !errors.Is(err, ErrWrongLogin) {
			t.Fatalf("%s: old password still works: %v", group, err)
		}
		if _, err := a.Login("192.168.1.10", goodPassword); err != nil {
			t.Fatalf("%s: new password: %v", group, err)
		}
		if b, _ := os.ReadFile(filepath.Join(st.Dir(), "..", "password.hash")); bcrypt.CompareHashAndPassword(b, []byte(old)) != nil {
			t.Fatalf("%s: the 1.x password file was changed", group)
		}
	}
}

func TestChangePasswordRoute(t *testing.T) {
	h := newReviewHarness(t, nil)
	if w := h.do("POST", "/api/auth/password", `{"current_password":"x","password":"another good one"}`, true); w.Code != http.StatusConflict {
		t.Fatalf("before setup: %d %s", w.Code, w.Body)
	}
	if err := h.s.cfg.Auth.Setup("127.0.0.1", goodPassword); err != nil {
		t.Fatal(err)
	}
	token, csrf := h.s.sess.create()
	h.cookie, h.csrf = &http.Cookie{Name: SessionCookie, Value: token}, csrf
	other, _ := h.s.sess.create()
	body := func(cur, next string) string {
		b, _ := json.Marshal(map[string]string{"current_password": cur, "password": next})
		return string(b)
	}
	cookie := h.cookie
	h.cookie = nil
	if w := h.do("POST", "/api/auth/password", body(goodPassword, "another good one"), true); w.Code != http.StatusUnauthorized {
		t.Fatalf("without session: %d", w.Code)
	}
	h.cookie = cookie
	if w := h.do("POST", "/api/auth/password", body(goodPassword, "another good one"), false); w.Code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", w.Code)
	}
	for _, c := range []struct {
		cur, next string
		code      int
		msg       string
	}{
		{"wrong password!", "another good one", http.StatusForbidden, "Current password is incorrect"},
		{goodPassword, "short", http.StatusBadRequest, "password must be"},
		{goodPassword, strings.Repeat("x", MaxPasswordLen+1), http.StatusBadRequest, "password must be"},
	} {
		w := h.do("POST", "/api/auth/password", body(c.cur, c.next), true)
		if w.Code != c.code || !strings.Contains(errorOf(t, w.Body.String()), c.msg) {
			t.Errorf("%q -> %q: %d %s", c.cur, c.next, w.Code, w.Body)
		}
	}
	// Past the wrong attempt's backoff.
	h.s.cfg.Auth.mu.Lock()
	clear(h.s.cfg.Auth.loginIP)
	h.s.cfg.Auth.mu.Unlock()
	w := h.do("POST", "/api/auth/password", body(goodPassword, "another good one"), true)
	if w.Code != http.StatusOK || errorOf(t, w.Body.String()) != "" {
		t.Fatalf("change: %d %s", w.Code, w.Body)
	}
	if _, ok := h.s.sess.lookup(other); ok {
		t.Fatal("another session survived the change")
	}
	if _, ok := h.s.sess.lookup(token); ok {
		t.Fatal("the old session survived the change")
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), SessionCookie+"=") {
		t.Fatal("no new session")
	}
	if _, err := h.s.cfg.Auth.Login("10.0.0.2", "another good one"); err != nil {
		t.Fatalf("new password: %v", err)
	}
}
