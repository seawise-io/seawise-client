package pair

import (
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
)

func TestData(t *testing.T) {
	ok := map[string]string{
		`{"data":{"a":"b"}}`:     `{"a":"b"}`,
		` { "data" : {} } `:      `{}`,
		`{"data":{"a":{"b":1}}}`: `{"a":{"b":1}}`,
	}
	for in, want := range ok {
		if got, err := data([]byte(in)); err != nil || string(got) != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	for _, in := range []string{``, `{}`, `[]`, `null`, `{"data":null}`, `{"data":[]}`, `{"data":"x"}`, `{"Data":{}}`, `{"data":{},"x":1}`, `{"data":{},"data":{}}`, `{"x":1,"data":{}}`, `{"data":{}} x`, `{"data":{}`, `{"data":`, `{"data"}`, `{1:{}}`} {
		if _, err := data([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseCodes(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	good := `{"data":{"user_code":"ABCDEFGHJK","device_code":"0123456789abcdef0123456789abcdef","expires_at":"2026-11-02T12:15:00.000Z","poll_url":"/api/servers/pair/status","key_id":"k"}}`
	c, err := parseCodes([]byte(good), now)
	if err != nil || c.user != "ABCDEFGHJK" || c.device != "0123456789abcdef0123456789abcdef" || c.keyID != "k" || !c.expires.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := parseCodes([]byte(strings.Replace(good, "12:15:00.000Z", "13:00:00Z", 1)), now); err != nil || !c.expires.Equal(now.Add(maxCodeLife)) {
		t.Fatalf("not capped: %+v %v", c, err)
	}
	if c, err := parseCodes([]byte(strings.Replace(good, "12:15:00.000Z", "12:20:00Z", 1)), now); err != nil || !c.expires.Equal(now.Add(maxCodeLife)) {
		t.Fatalf("cap boundary: %+v %v", c, err)
	}
	if _, err := parseCodes([]byte(strings.Replace(good, "12:15:00.000Z", "12:00:00Z", 1)), now); err == nil {
		t.Fatal("expiry at now accepted")
	}
	if _, err := parseCodes([]byte(strings.Replace(good, "12:15:00.000Z", "12:00:01Z", 1)), now); err != nil {
		t.Fatal("expiry just ahead refused")
	}
	for _, bad := range []string{
		strings.Replace(good, "ABCDEFGHJK", "ABCDEFGHJI", 1),
		strings.Replace(good, "ABCDEFGHJK", "ABCDEFGHJKL", 1),
		strings.Replace(good, "0123456789abcdef0123456789abcdef", "0123456789ABCDEF0123456789abcdef", 1),
		strings.Replace(good, "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcde", 1),
		strings.Replace(good, `"key_id":"k"`, `"key_id":null`, 1),
		strings.Replace(good, `,"poll_url":"/api/servers/pair/status"`, `,"frp_token":"x"`, 1),
	} {
		if _, err := parseCodes([]byte(bad), now); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParsePairing(t *testing.T) {
	good := `{"data":{"server_id":"00000000-0000-4000-8000-000000000001","server_name":"nas","user_id":"a0000000-0000-4000-8000-000000000001","device_id":"d0000000-0000-4000-8000-000000000001","key_id":"k"}}`
	p, err := parsePairing([]byte(good))
	if err != nil || p.serverName != "nas" || p.keyID != "k" || p.userID == "" {
		t.Fatalf("%+v %v", p, err)
	}
	minimal := `{"data":{"server_id":"00000000-0000-4000-8000-000000000001","device_id":"d0000000-0000-4000-8000-000000000001","key_id":"k"}}`
	if p, err := parsePairing([]byte(minimal)); err != nil || p.serverName != "" || p.userID != "" {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := parsePairing([]byte(strings.Replace(good, `"nas"`, `"  "`, 1))); err != nil || p.serverName != "" {
		t.Fatalf("blank name: %+v %v", p, err)
	}
	for _, bad := range []string{
		strings.Replace(good, `"server_id":"00000000-0000-4000-8000-000000000001"`, `"server_id":"x"`, 1),
		strings.Replace(good, `"device_id":"d0000000-0000-4000-8000-000000000001"`, `"device_id":"D0000000-0000-4000-8000-000000000001"`, 1),
		strings.Replace(good, `"user_id":"a0000000-0000-4000-8000-000000000001"`, `"user_id":"u1"`, 1),
		strings.Replace(good, `"key_id":"k"`, `"key_id":"k","frp_token":"t"`, 1),
		`{"server_id":"00000000-0000-4000-8000-000000000001"}`,
	} {
		if _, err := parsePairing([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestCleanName(t *testing.T) {
	ok := map[string]string{"": defaultName, "  ": defaultName, " nas ": "nas", strings.Repeat("é", 100): strings.Repeat("é", 100), "a b": "a b"}
	for in, want := range ok {
		if got, err := cleanName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{strings.Repeat("é", 101), "a\tb", "a\u0085b", "\xff", "a\x7fb"} {
		if _, err := cleanName(in); err != ErrInvalidName {
			t.Errorf("%q accepted", in)
		}
	}
}

func FuzzParseCodes(f *testing.F) {
	f.Add([]byte(`{"data":{"user_code":"ABCDEFGHJK","device_code":"0123456789abcdef0123456789abcdef","expires_at":"2026-11-02T12:15:00.000Z","key_id":"k"}}`))
	f.Add([]byte(`{"data":{"user_code":"ABCDEFGHJK","user_code":"ABCDEFGHJK"}}`))
	f.Add([]byte(`{"data":{}}`))
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := parseCodes(b, now)
		if err != nil {
			return
		}
		if !userCodeRe.MatchString(c.user) || !deviceCodeRe.MatchString(c.device) || !c.expires.After(now) || c.expires.After(now.Add(maxCodeLife)) {
			t.Fatalf("accepted %+v", c)
		}
	})
}

func FuzzParsePairing(f *testing.F) {
	f.Add([]byte(`{"data":{"server_id":"00000000-0000-4000-8000-000000000001","server_name":"nas","device_id":"d0000000-0000-4000-8000-000000000001","key_id":"k"}}`))
	f.Add([]byte(`{"data":{"server_id":null}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parsePairing(b)
		if err != nil {
			return
		}
		if !claims.ValidUUID(p.serverID) || !claims.ValidUUID(p.deviceID) || (p.userID != "" && !claims.ValidUUID(p.userID)) {
			t.Fatalf("accepted %+v", p)
		}
		if p.serverName != "" && (utf8.RuneCountInString(p.serverName) > maxName || strings.ContainsFunc(p.serverName, unicode.IsControl)) {
			t.Fatalf("name %q", p.serverName)
		}
	})
}

func FuzzCleanName(f *testing.F) {
	for _, s := range []string{"nas", "", " a ", "a\nb", strings.Repeat("x", 101)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := cleanName(s)
		if err != nil {
			return
		}
		if n == "" || !utf8.ValidString(n) || utf8.RuneCountInString(n) > maxName || strings.ContainsFunc(n, unicode.IsControl) || n != strings.TrimSpace(n) {
			t.Fatalf("%q -> %q", s, n)
		}
	})
}
