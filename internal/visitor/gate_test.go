package visitor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

const (
	appA  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000a1"
	appB  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000b2"
	sidA  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000c3"
	sidB  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000c4"
	userA = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000d5"
	acctA = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000e6"
	jtiA  = "6d1f3c2a-8b4e-4f7a-9c0d-0000000000f7"
	exp0  = int64(1_800_000_000)
)

func testKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("visitor-gate-test/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func compact(k ed25519.PrivateKey, typ string, claims any) string {
	pub := k.Public().(ed25519.PublicKey)
	h, _ := json.Marshal(map[string]string{"typ": typ, "alg": "EdDSA", "kid": protocol.KeyID(pub)})
	p, _ := json.Marshal(claims)
	in := b64url.EncodeToString(h) + "." + b64url.EncodeToString(p)
	return in + "." + b64url.EncodeToString(ed25519.Sign(k, []byte(in)))
}

func userClaims(aud, sid string, exp int64) map[string]any {
	return map[string]any{"sid": sid, "sub": userA, "epoch": 0, "aud": aud, "acct": acctA, "gen": 1, "av": 3, "iat": exp - 900, "exp": exp}
}

func token(aud, sid string, exp int64) string {
	return compact(testKey("visitor"), TypVisitor, userClaims(aud, sid, exp))
}

func staleOk(k ed25519.PrivateKey, edge, aud, sid string, until, iat int64) string {
	return compact(k, TypStaleOk, map[string]any{"edge": edge, "aud": aud, "sid": sid, "until": until, "iat": iat})
}

// longEdge is an edge id of exactly 63 characters.
var longEdge = "edge-" + strings.Repeat("a", 54) + "-b-1"

// groupOrderLE is the Ed25519 group order, little-endian.
var groupOrderLE = func() []byte {
	n, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	be := n.FillBytes(make([]byte, 32))
	le := make([]byte, 32)
	for i := range le {
		le[i] = be[31-i]
	}
	return le
}()

// withS replaces the S half of a token's signature.
func withS(tok string, s []byte) string {
	i := strings.LastIndexByte(tok, '.')
	sig, _ := b64url.DecodeString(tok[i+1:])
	copy(sig[32:], s)
	return tok[:i+1] + b64url.EncodeToString(sig)
}

func testKeySet(t testing.TB) *protocol.KeySet {
	return keySet(t, []protocol.KeySetEntry{
		entry(testKey("visitor"), protocol.RoleVisitor, "", protocol.StatusActive),
		entry(testKey("visitor-next"), protocol.RoleVisitor, "", protocol.StatusNext),
		entry(testKey("visitor-revoked"), protocol.RoleVisitor, "", protocol.StatusRevoked),
		entry(testKey("edge"), protocol.RoleEdge, "edge-us-east-0", protocol.StatusActive),
		entry(testKey("edge-revoked"), protocol.RoleEdge, "edge-us-east-1", protocol.StatusRevoked),
		entry(testKey("edge-long"), protocol.RoleEdge, longEdge, protocol.StatusActive),
		entry(testKey("control"), protocol.RoleControl, "", protocol.StatusActive),
		entry(testKey("snapshot"), protocol.RoleSnapshot, "", protocol.StatusActive),
	})
}

type fixture struct {
	gate *Gate
	ks   *protocol.KeySet
	mode Mode
	now  int64
	logs *bytes.Buffer
	mu   sync.Mutex
}

func newFixture(t testing.TB) *fixture {
	f := &fixture{ks: testKeySet(t), mode: Observe, now: exp0 - 60, logs: &bytes.Buffer{}}
	var err error
	f.gate, err = New(Config{
		KeySet: func() *protocol.KeySet { return f.ks },
		Mode:   func() Mode { return f.mode },
		Now:    func() time.Time { return time.Unix(f.now, 0) },
		Logger: slog.New(slog.NewTextHandler(syncWriter{f}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type syncWriter struct{ f *fixture }

func (w syncWriter) Write(b []byte) (int, error) {
	w.f.mu.Lock()
	defer w.f.mu.Unlock()
	return w.f.logs.Write(b)
}

func TestGateDecisions(t *testing.T) {
	valid := token(appA, sidA, exp0)
	shareToken := compact(testKey("visitor"), TypVisitor, map[string]any{"sid": sidA, "jti": jtiA, "aud": appA, "acct": acctA, "gen": 1, "av": 0, "iat": exp0 - 900, "exp": exp0})
	cappedClaims := userClaims(appA, sidA, exp0)
	cappedClaims["iat"] = exp0 - 899
	capped := compact(testKey("visitor"), TypVisitor, cappedClaims)
	edge := testKey("edge")
	for _, c := range []struct {
		name string
		req  Request
		now  int64
		code string
	}{
		{"valid", Request{AppID: appA, Token: valid}, exp0 - 60, CodeValid},
		{"share session", Request{AppID: appA, Token: compact(testKey("visitor"), TypVisitor, map[string]any{"sid": sidA, "jti": jtiA, "aud": appA, "acct": acctA, "gen": 1, "av": 0, "iat": exp0 - 900, "exp": exp0})}, exp0, CodeValid},
		{"next key", Request{AppID: appA, Token: compact(testKey("visitor-next"), TypVisitor, userClaims(appA, sidA, exp0))}, exp0, CodeValid},
		{"revoked key", Request{AppID: appA, Token: compact(testKey("visitor-revoked"), TypVisitor, userClaims(appA, sidA, exp0))}, exp0, "unknown_key"},
		{"control key", Request{AppID: appA, Token: compact(testKey("control"), TypVisitor, userClaims(appA, sidA, exp0))}, exp0, "unknown_key"},
		{"edge key", Request{AppID: appA, Token: compact(edge, TypVisitor, userClaims(appA, sidA, exp0))}, exp0, "unknown_key"},
		{"snapshot key", Request{AppID: appA, Token: compact(testKey("snapshot"), TypVisitor, userClaims(appA, sidA, exp0))}, exp0, "unknown_key"},
		{"unknown key", Request{AppID: appA, Token: compact(testKey("other"), TypVisitor, userClaims(appA, sidA, exp0))}, exp0, "unknown_key"},
		{"stale-ok as token", Request{AppID: appA, Token: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0)}, exp0, "bad_typ"},
		{"wrong app", Request{AppID: appB, Token: valid}, exp0, CodeWrongApp},
		{"app id not canonical", Request{AppID: strings.ToUpper(appA), Token: valid}, exp0, CodeWrongApp},
		{"missing", Request{AppID: appA}, exp0, CodeMissing},
		{"stale-ok without token", Request{AppID: appA, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0)}, exp0, CodeMissing},
		{"malformed", Request{AppID: appA, Token: "a.b.c"}, exp0, "malformed"},
		{"public, no token", Request{AppID: appA, Public: true}, exp0, CodePublic},
		{"public, valid token", Request{AppID: appA, Public: true, Token: valid}, exp0, CodeValid},
		{"public, bad token", Request{AppID: appA, Public: true, Token: "a.b.c"}, exp0, CodePublic},
		{"public, other app token", Request{AppID: appB, Public: true, Token: valid}, exp0, CodePublic},
		{"iat at leeway", Request{AppID: appA, Token: valid}, exp0 - 900 - 300, CodeValid},
		{"iat past leeway", Request{AppID: appA, Token: valid}, exp0 - 900 - 301, CodeNotYetValid},
		{"exp at leeway", Request{AppID: appA, Token: valid}, exp0 + 300, CodeValid},
		{"exp past leeway", Request{AppID: appA, Token: valid}, exp0 + 301, CodeExpired},
		{"stale ok", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, CodeStaleOk},
		{"stale ok at its end", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1700)}, exp0 + 1830, CodeStaleOk},
		{"stale past its end", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1700)}, exp0 + 1831, "stale_expired"},
		{"stale other sid", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidB, exp0+1800, exp0+1000)}, exp0 + 1000, "stale_not_bound"},
		{"stale until off", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1799, exp0+1000)}, exp0 + 1000, "stale_not_bound"},
		{"stale other edge name", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-1", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, "stale_malformed"},
		{"stale revoked edge", Request{AppID: appA, Token: valid, StaleOk: staleOk(testKey("edge-revoked"), "edge-us-east-1", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, "stale_unknown_key"},
		{"stale signed by visitor key", Request{AppID: appA, Token: valid, StaleOk: staleOk(testKey("visitor"), "edge-us-east-0", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, "stale_unknown_key"},
		{"stale for other app", Request{AppID: appB, Token: token(appB, sidA, exp0), StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, "stale_not_bound"},
		{"stale iat at skew", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1030)}, exp0 + 1000, CodeStaleOk},
		{"stale iat past skew", Request{AppID: appA, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1031)}, exp0 + 1000, "stale_not_yet_valid"},
		{"stale edge id of 63", Request{AppID: appA, Token: valid, StaleOk: staleOk(testKey("edge-long"), longEdge, appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, CodeStaleOk},
		{"s equal to the group order", Request{AppID: appA, Token: withS(valid, groupOrderLE)}, exp0, "bad_signature"},
		{"stale for a share session", Request{AppID: appA, Token: shareToken, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, CodeStaleIneligible},
		{"stale for a capped user token", Request{AppID: appA, Token: capped, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, CodeStaleIneligible},
		{"capped user token in its window", Request{AppID: appA, Token: capped}, exp0, CodeValid},
		{"stale ignored while token valid", Request{AppID: appA, Token: valid, StaleOk: "junk"}, exp0, CodeValid},
		{"bad stale past leeway", Request{AppID: appA, Token: valid, StaleOk: "junk"}, exp0 + 301, "stale_malformed"},
		{"expired token on wrong app with stale", Request{AppID: appB, Token: valid, StaleOk: staleOk(edge, "edge-us-east-0", appA, sidA, exp0+1800, exp0+1000)}, exp0 + 1000, CodeWrongApp},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, mode := range []Mode{Observe, Enforce} {
				f := newFixture(t)
				f.now, f.mode = c.now, mode
				d := f.gate.Check(c.req)
				if d.Code != c.code {
					t.Fatalf("%s: code %s, want %s", mode, d.Code, c.code)
				}
				accepted := c.code == CodeValid || c.code == CodePublic || c.code == CodeStaleOk
				if d.Valid() != accepted || d.Mode != mode {
					t.Fatalf("%s: valid %v mode %s", mode, d.Valid(), d.Mode)
				}
				if want := accepted || mode == Observe; d.Allow != want {
					t.Fatalf("%s: allow %v", mode, d.Allow)
				}
				wantReply := pb.ReplyCode_ACCEPTED
				if !d.Allow {
					wantReply = pb.ReplyCode_TOKEN_REJECTED
				}
				if d.Reply() != wantReply {
					t.Fatalf("%s: reply %v", mode, d.Reply())
				}
			}
		})
	}
}

func TestLoggedAppIsAUUID(t *testing.T) {
	f := newFixture(t)
	f.gate.Check(Request{AppID: "x\nlevel=ERROR msg=forged"})
	if out := f.logs.String(); strings.Contains(out, "forged") || !strings.Contains(out, "app=invalid") {
		t.Fatalf("log: %s", out)
	}
}

func TestDecisionSessionReference(t *testing.T) {
	f := newFixture(t)
	d := f.gate.Check(Request{AppID: appA, Token: token(appA, sidA, exp0)})
	sum := sha256.Sum256([]byte(sidA))
	if d.Session != "sid:"+b64hex(sum[:6]) || len(d.Session) != 16 || d.Kind != "user" {
		t.Fatalf("session %q kind %q", d.Session, d.Kind)
	}
	if d2 := f.gate.Check(Request{AppID: appA, Token: token(appA, sidB, exp0)}); d2.Session == d.Session {
		t.Fatal("sessions share a reference")
	}
	if d3 := f.gate.Check(Request{AppID: appA, Public: true}); d3.Session != "" || d3.Kind != "" {
		t.Fatalf("anonymous decision %+v", d3)
	}
	if d4 := f.gate.Check(Request{AppID: appB, Token: token(appA, sidA, exp0)}); d4.Session != "" {
		t.Fatal("a refused token gives a session reference")
	}
}

func b64hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestNoKeySet(t *testing.T) {
	f := newFixture(t)
	f.ks = nil
	for _, mode := range []Mode{Observe, Enforce} {
		f.mode = mode
		d := f.gate.Check(Request{AppID: appA, Token: token(appA, sidA, exp0)})
		if d.Code != CodeNoKeySet || d.Allow != (mode == Observe) {
			t.Fatalf("%s: %+v", mode, d)
		}
		if d := f.gate.Check(Request{AppID: appA, Public: true}); d.Code != CodePublic || !d.Allow {
			t.Fatalf("%s public: %+v", mode, d)
		}
	}
}

func TestUnknownModeIsObserve(t *testing.T) {
	f := newFixture(t)
	f.mode = "strict"
	if d := f.gate.Check(Request{AppID: appA}); !d.Allow || d.Mode != Observe {
		t.Fatalf("%+v", d)
	}
	g, err := New(Config{KeySet: func() *protocol.KeySet { return nil }, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if d := g.Check(Request{AppID: appA}); !d.Allow || d.Mode != Observe {
		t.Fatalf("nil mode func: %+v", d)
	}
}

// The gate never falls back to the system clock or to no key set.
func TestNewRequiresClockAndKeySet(t *testing.T) {
	ks := func() *protocol.KeySet { return nil }
	if _, err := New(Config{KeySet: ks}); err == nil {
		t.Fatal("no clock accepted")
	}
	if _, err := New(Config{Now: time.Now}); err == nil {
		t.Fatal("no key set accepted")
	}
}

// A new key set is used for the next request; nothing is decided from a
// cached answer.
func TestKeySetChangeTakesEffect(t *testing.T) {
	f := newFixture(t)
	f.mode = Enforce
	tok := token(appA, sidA, exp0)
	if d := f.gate.Check(Request{AppID: appA, Token: tok}); !d.Allow {
		t.Fatal("refused")
	}
	f.ks = keySet(t, []protocol.KeySetEntry{entry(testKey("visitor"), protocol.RoleVisitor, "", protocol.StatusRevoked), entry(testKey("visitor-next"), protocol.RoleVisitor, "", protocol.StatusActive)})
	if d := f.gate.Check(Request{AppID: appA, Token: tok}); d.Allow || d.Code != "unknown_key" {
		t.Fatalf("after revoke: %+v", d)
	}
	f.mode = Observe
	if d := f.gate.Check(Request{AppID: appA, Token: tok}); !d.Allow {
		t.Fatal("observe refused")
	}
}

func TestLogsNeverHoldTokens(t *testing.T) {
	f := newFixture(t)
	tok := token(appA, sidA, exp0)
	stale := staleOk(testKey("edge"), "edge-us-east-0", appA, sidB, exp0+1800, exp0+1000)
	f.now = exp0 + 1000
	for _, mode := range []Mode{Observe, Enforce} {
		f.mode = mode
		for i := 0; i < 3; i++ {
			f.gate.Check(Request{AppID: appA, Token: tok, StaleOk: stale})
			f.gate.Check(Request{AppID: appB, Token: tok})
			f.gate.Check(Request{AppID: appA})
		}
		f.now += 61
	}
	out := f.logs.String()
	for _, secret := range append(strings.Split(tok, "."), strings.Split(stale, ".")...) {
		if strings.Contains(out, secret[:12]) {
			t.Fatalf("log holds token bytes: %s", out)
		}
	}
	for _, s := range []string{sidA, sidB, userA} {
		if strings.Contains(out, s) {
			t.Fatalf("log holds an identifier: %s", out)
		}
	}
	for _, want := range []string{"code=stale_not_bound", "code=wrong_app", "code=missing", "mode=observe", "mode=enforce"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %s: %s", want, out)
		}
	}
}

func TestRefusalLogsAreThrottled(t *testing.T) {
	f := newFixture(t)
	f.mode = Enforce
	for i := 0; i < 50; i++ {
		f.gate.Check(Request{AppID: appA})
	}
	if n := strings.Count(f.logs.String(), "code=missing"); n != 1 {
		t.Fatalf("%d lines", n)
	}
	f.now += 59
	f.gate.Check(Request{AppID: appA})
	f.gate.Check(Request{AppID: appA, Token: "x"})
	if n := strings.Count(f.logs.String(), "code=missing"); n != 1 {
		t.Fatalf("%d lines after 59 s", n)
	}
	if !strings.Contains(f.logs.String(), "code=malformed") {
		t.Fatal("another code was throttled")
	}
	f.now++
	f.gate.Check(Request{AppID: appA})
	if n := strings.Count(f.logs.String(), "code=missing"); n != 2 {
		t.Fatalf("%d lines after 60 s", n)
	}
	before := f.logs.Len()
	f.gate.Check(Request{AppID: appA, Token: token(appA, sidA, exp0)})
	f.gate.Check(Request{AppID: appA, Public: true})
	if f.logs.Len() != before {
		t.Fatal("an accepted request was logged")
	}
}

func TestStatusCounts(t *testing.T) {
	f := newFixture(t)
	f.gate.Check(Request{AppID: appA, Token: token(appA, sidA, exp0)})
	f.gate.Check(Request{AppID: appA, Token: token(appA, sidA, exp0)})
	f.gate.Check(Request{AppID: appA})
	f.mode = Enforce
	f.gate.Check(Request{AppID: appA, Public: true})
	st := f.gate.Status()
	if st.Mode != Enforce || st.Counts[CodeValid] != 2 || st.Counts[CodeMissing] != 1 || st.Counts[CodePublic] != 1 || len(st.Counts) != 3 {
		t.Fatalf("%+v", st)
	}
	st.Counts[CodeValid] = 99
	if f.gate.Status().Counts[CodeValid] != 2 {
		t.Fatal("status shares its map")
	}
}

func TestConcurrentChecks(t *testing.T) {
	f := newFixture(t)
	tok := token(appA, sidA, exp0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if d := f.gate.Check(Request{AppID: appA, Token: tok}); d.Code != CodeValid {
					t.Errorf("code %s", d.Code)
				}
				_ = f.gate.Status()
			}
		}()
	}
	wg.Wait()
	if f.gate.Status().Counts[CodeValid] != 400 {
		t.Fatal("lost counts")
	}
}
