package visitor

import (
	"strings"
	"testing"
)

func FuzzVerifyToken(f *testing.F) {
	env := loadJWS(f)
	for _, c := range env.file.Cases {
		if c.Kind == "visitor" && c.TokenRepeat == nil {
			f.Add(c.Token)
		}
	}
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := VerifyToken(tok, env.keys)
		if err != nil {
			if ReasonOf(err) == "" || strings.Contains(err.Error(), tok) && len(tok) > 16 {
				t.Fatalf("error %v", err)
			}
			return
		}
		if c.Exp < c.Iat || !uuidRE.MatchString(c.Aud) || !uuidRE.MatchString(c.Sid) || (c.Kind != "user" && c.Kind != "share_link") {
			t.Fatalf("accepted %+v", c)
		}
	})
}

func FuzzVerifyStaleOk(f *testing.F) {
	env := loadJWS(f)
	for _, c := range env.file.Cases {
		if c.Kind == "stale_ok" && c.TokenRepeat == nil {
			f.Add(c.Token, c.Now)
		}
	}
	f.Fuzz(func(t *testing.T, tok string, now int64) {
		c, err := VerifyStaleOk(tok, env.keys, now)
		if err != nil {
			if ReasonOf(err) == "" {
				t.Fatalf("error %v", err)
			}
			return
		}
		if c.Until <= c.Iat || c.Until-c.Iat > StaleWindow || now > c.Until+staleSkew || c.Iat-staleSkew > now {
			t.Fatalf("accepted %+v at %d", c, now)
		}
	})
}

func FuzzStrictJSON(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `{"a":[1,{"b":"\ud800"}]}`, `{"a":1e999}`, `{}`, `[`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseJSON(b)
	})
}

// The gate never panics and never accepts in enforce mode without a
// verified token for the app.
func FuzzGate(f *testing.F) {
	f.Add(appA, false, token(appA, sidA, exp0), "", exp0)
	f.Add(appA, false, token(appA, sidA, exp0), staleOk(testKey("edge"), "edge-us-east-0", appA, sidA, exp0+1800, exp0+900), exp0+900)
	f.Add(appB, true, "", "x", int64(0))
	fx := newFixture(f)
	fx.mode = Enforce
	f.Fuzz(func(t *testing.T, app string, public bool, tok, stale string, now int64) {
		fx.mu.Lock()
		fx.now = now
		fx.mu.Unlock()
		d := fx.gate.Check(Request{AppID: app, Public: public, Token: tok, StaleOk: stale})
		if !d.Allow {
			return
		}
		if public {
			return
		}
		c, err := VerifyToken(tok, NewKeys(fx.ks))
		if err != nil || c.Aud != app {
			t.Fatalf("accepted %q for %q: %+v", tok, app, d)
		}
	})
}
