package adminui

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

const (
	SessionCookie = "__Host-seawise_session"
	SessionTTL    = 8 * time.Hour
	MaxSessions   = 64
)

type session struct {
	csrf    string
	created time.Time
	expires time.Time
}

// sessions keeps sessions by the SHA-256 of their token, so the map never
// holds a usable credential.
type sessions struct {
	mu  sync.Mutex
	m   map[[32]byte]*session
	now func() time.Time
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{m: map[[32]byte]*session{}, now: now}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessions) create() (token, csrf string) {
	token, csrf = randomToken(32), randomToken(32)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	for len(s.m) >= MaxSessions {
		var oldest [32]byte
		var t time.Time
		for k, v := range s.m {
			if t.IsZero() || v.created.Before(t) {
				oldest, t = k, v.created
			}
		}
		delete(s.m, oldest)
	}
	s.m[sha256.Sum256([]byte(token))] = &session{csrf: csrf, created: now, expires: now.Add(SessionTTL)}
	return token, csrf
}

func (s *sessions) prune(now time.Time) {
	for k, v := range s.m {
		if !now.Before(v.expires) {
			delete(s.m, k)
		}
	}
}

func (s *sessions) lookup(token string) (*session, bool) {
	if token == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[sha256.Sum256([]byte(token))]
	if !ok || !s.now().Before(v.expires) {
		return nil, false
	}
	cp := *v
	return &cp, true
}

func (s *sessions) remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sha256.Sum256([]byte(token)))
}

func (s *sessions) removeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = map[[32]byte]*session{}
}

func (s *sessions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

func equalSecret(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", MaxAge: int(SessionTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
