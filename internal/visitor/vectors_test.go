package visitor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/seawise/client/internal/protocol"
)

// testdata/edge holds the platform edge's jws and agent vectors, copied
// unchanged; the outcome (and claims) must match for every visitor and
// stale-ok case.

type vectorKey struct {
	Name string `json:"name"`
	Seed string `json:"seed"`
	Kid  string `json:"kid"`
	Edge string `json:"edge"`
}

type jwsCase struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Token       string `json:"token"`
	TokenRepeat *struct {
		Char  string `json:"char"`
		Count int    `json:"count"`
	} `json:"token_repeat"`
	Now    int64           `json:"now"`
	Expect string          `json:"expect"`
	Claims json.RawMessage `json:"claims"`
}

func (c jwsCase) token() string {
	if c.TokenRepeat != nil {
		return strings.Repeat(c.TokenRepeat.Char, c.TokenRepeat.Count)
	}
	return c.Token
}

type jwsFile struct {
	Format    string              `json:"format"`
	Keys      []vectorKey         `json:"keys"`
	Keysets   map[string][]string `json:"keysets"`
	KeyOwners map[string]string   `json:"key_owners"`
	Cases     []jwsCase           `json:"cases"`
}

func readJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func seedKey(t testing.TB, k vectorKey) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(k.Seed)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if got := protocol.KeyID(priv.Public().(ed25519.PublicKey)); got != k.Kid {
		t.Fatalf("key %s: kid %s, vector %s", k.Name, got, k.Kid)
	}
	return priv
}

// keySet signs entries into a verified key set with a throwaway root.
func keySet(t testing.TB, entries []protocol.KeySetEntry) *protocol.KeySet {
	t.Helper()
	seed := sha256.Sum256([]byte("visitor-test-root"))
	root := ed25519.NewKeyFromSeed(seed[:])
	tok, err := protocol.NewKeySet(root, 1, 1_700_000_000, entries)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := protocol.VerifyKeySet(tok, []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func entry(priv ed25519.PrivateKey, role, name, status string) protocol.KeySetEntry {
	pub := priv.Public().(ed25519.PublicKey)
	return protocol.KeySetEntry{KID: protocol.KeyID(pub), Role: role, X: b64url.EncodeToString(pub), Status: status, Name: name}
}

type jwsEnv struct {
	file jwsFile
	keys *Keys
}

func loadJWS(t testing.TB) *jwsEnv {
	t.Helper()
	env := &jwsEnv{}
	readJSON(t, "../../testdata/edge/jws/vectors.json", &env.file)
	if env.file.Format != "edge_jws" {
		t.Fatalf("format %q", env.file.Format)
	}
	privs := map[string]ed25519.PrivateKey{}
	for _, k := range env.file.Keys {
		privs[k.Name] = seedKey(t, k)
	}
	roles := map[string]string{"visitor": protocol.RoleVisitor, "stale_ok": protocol.RoleEdge, "snapshot": protocol.RoleSnapshot, "share": protocol.RoleRelease}
	var entries []protocol.KeySetEntry
	seen := map[string]bool{}
	for kind, names := range env.file.Keysets {
		role, ok := roles[kind]
		if !ok {
			continue
		}
		for _, n := range names {
			if seen[n] {
				t.Fatalf("key %s in two kinds", n)
			}
			seen[n] = true
			entries = append(entries, entry(privs[n], role, env.file.KeyOwners[n], protocol.StatusActive))
		}
	}
	env.keys = NewKeys(keySet(t, entries))
	return env
}

func (env *jwsEnv) run(kind, token string, now int64) (string, any) {
	var (
		v   any
		err error
	)
	switch kind {
	case "visitor":
		var c *Token
		if c, err = VerifyToken(token, env.keys); err == nil {
			v = c.jsValue()
		}
	case "stale_ok":
		var c *StaleOk
		if c, err = VerifyStaleOk(token, env.keys, now); err == nil {
			v = c.jsValue()
		}
	default:
		return "skip", nil
	}
	if err != nil {
		return string(ReasonOf(err)), nil
	}
	return "ok", v
}

func f64(n int64) float64 { return float64(n) }

func (t *Token) jsValue() any {
	o := map[string]any{"sid": t.Sid, "aud": t.Aud, "acct": t.Acct, "gen": f64(t.Gen), "av": f64(t.Av), "iat": f64(t.Iat), "exp": f64(t.Exp), "kind": t.Kind}
	if t.Kind == "user" {
		o["sub"], o["epoch"] = t.Sub, f64(t.Epoch)
	} else {
		o["jti"] = t.Jti
	}
	return o
}

func (c *StaleOk) jsValue() any {
	return map[string]any{"edge": c.Edge, "aud": c.Aud, "sid": c.Sid, "until": f64(c.Until), "iat": f64(c.Iat)}
}

func TestEdgeVectors(t *testing.T) {
	env := loadJWS(t)
	ran := map[string]int{}
	for _, c := range env.file.Cases {
		got, claims := env.run(c.Kind, c.token(), c.Now)
		if got == "skip" {
			continue
		}
		ran[c.Kind]++
		t.Run(c.Name, func(t *testing.T) {
			if got != c.Expect {
				t.Fatalf("got %s, want %s", got, c.Expect)
			}
			if got != "ok" {
				return
			}
			var want any
			if err := json.Unmarshal(c.Claims, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(claims, want) {
				t.Fatalf("claims differ\n got %#v\nwant %#v", claims, want)
			}
		})
	}
	if ran["visitor"] < 80 || ran["stale_ok"] < 20 {
		t.Fatalf("ran %v", ran)
	}
}

type staleCase struct {
	Name    string `json:"name"`
	Visitor string `json:"visitor"`
	Header  string `json:"header"`
	Now     int64  `json:"now"`
	Expect  string `json:"expect"`
}

type staleFile struct {
	Format      string      `json:"format"`
	Window      int64       `json:"window"`
	Keys        []vectorKey `json:"keys"`
	VisitorKeys []string    `json:"visitor_keys"`
	EdgeKeys    []string    `json:"edge_keys"`
	Cases       []staleCase `json:"cases"`
}

func loadStale(t testing.TB) (staleFile, *Keys) {
	t.Helper()
	var f staleFile
	readJSON(t, "../../testdata/edge/agent/stale_ok.json", &f)
	if f.Format != "stale_ok" || f.Window != StaleWindow {
		t.Fatalf("format %q window %d", f.Format, f.Window)
	}
	byName := map[string]vectorKey{}
	for _, k := range f.Keys {
		byName[k.Name] = k
	}
	var entries []protocol.KeySetEntry
	for _, n := range f.VisitorKeys {
		entries = append(entries, entry(seedKey(t, byName[n]), protocol.RoleVisitor, "", protocol.StatusActive))
	}
	for _, n := range f.EdgeKeys {
		entries = append(entries, entry(seedKey(t, byName[n]), protocol.RoleEdge, byName[n].Edge, protocol.StatusActive))
	}
	return f, NewKeys(keySet(t, entries))
}

func TestStaleOkVectors(t *testing.T) {
	f, keys := loadStale(t)
	if len(f.Cases) < 15 {
		t.Fatalf("only %d cases", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := VerifyToken(c.Visitor, keys)
			if err != nil {
				t.Fatalf("visitor token: %v", err)
			}
			got := "ok"
			if _, err := CheckStaleOk(c.Header, v, keys, c.Now); err != nil {
				got = string(ReasonOf(err))
			}
			if got != c.Expect {
				t.Fatalf("got %s, want %s", got, c.Expect)
			}
		})
	}
}

// Changing any bit of a valid token never verifies.
func TestSingleBitChangeNeverVerifies(t *testing.T) {
	env := loadJWS(t)
	seen := map[string]bool{}
	checked := 0
	for _, c := range env.file.Cases {
		if c.Expect != "ok" || seen[c.Kind] || (c.Kind != "visitor" && c.Kind != "stale_ok") {
			continue
		}
		seen[c.Kind] = true
		tok := []byte(c.Token)
		for i := range tok {
			for bit := 0; bit < 8; bit++ {
				m := append([]byte(nil), tok...)
				m[i] ^= 1 << bit
				if got, _ := env.run(c.Kind, string(m), c.Now); got == "ok" {
					t.Fatalf("%s: byte %d bit %d still verifies", c.Name, i, bit)
				}
				checked++
			}
		}
	}
	if len(seen) != 2 || checked < 4000 {
		t.Fatalf("only %d mutations checked", checked)
	}
}

func TestErrorsDoNotQuoteInput(t *testing.T) {
	env := loadJWS(t)
	for _, c := range env.file.Cases {
		if c.Expect == "ok" || c.TokenRepeat != nil || (c.Kind != "visitor" && c.Kind != "stale_ok") {
			continue
		}
		var err error
		if c.Kind == "visitor" {
			_, err = VerifyToken(c.Token, env.keys)
		} else {
			_, err = VerifyStaleOk(c.Token, env.keys, c.Now)
		}
		if err == nil {
			t.Fatalf("%s: no error", c.Name)
		}
		msg := err.Error()
		for _, seg := range strings.Split(c.Token, ".") {
			if len(seg) >= 8 && strings.Contains(msg, seg[:8]) {
				t.Fatalf("%s: %q quotes the token", c.Name, msg)
			}
		}
	}
}

func TestStrictNumbers(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"a":1}`: true, `{"a":1.0}`: true, `{"a":1e400}`: false, `{"a":01}`: false, `{"a":-}`: false,
		`{"a":1.}`: false, `{"a":1e}`: false, `{"a":null}`: false, `{"a":[true,false]}`: true, `{"a":"A"}`: true,
		`{"a":"\x"}`: false, `{"a":"\ud800"}`: true, `{"a":"\ud83d\ude00"}`: true, `{"a":"\uzzzz"}`: false, `{"a":1,}`: false,
		`{"a":[[[[[[[1]]]]]]]}`: true, `{"a":[[[[[[[[1]]]]]]]]}`: false, `{"a":{}}`: true, `{"a":[]}`: true, ` {"a":1} `: true,
		`{"a":-1}`: true, `{"a":-0.5e-3}`: true, `{"a":-x}`: false, `{"a":9}`: true, `{"a":90}`: true,
		"{\"a\":\"\x1f\"}": false, "{\"a\":\"\x7f\"}": true,
		`{"a":[],"b":[],"c":{},"d":[],"e":{},"f":[],"g":[],"h":[],"i":[{"j":[[[[[1]]]]]}]}`: true,
	} {
		_, err := parseJSON([]byte(in))
		if (err == nil) != ok {
			t.Errorf("%s: err %v", in, err)
		}
	}
	for in, want := range map[string]string{
		`{"a":"\ud800"}`:        "\xed\xa0\x80",
		`{"a":"\udbff"}`:        "\xed\xaf\xbf",
		`{"a":"\udc00\udc00"}`:  "\xed\xb0\x80\xed\xb0\x80",
		`{"a":"\ud83d\ude00"}`:  "\xf0\x9f\x98\x80",
		`{"a":"\ud83dx\ude00"}`: "\xed\xa0\xbdx\xed\xb8\x80",
		`{"a":"\ud83d\n"}`:      "\xed\xa0\xbd\n",
		`{"a":"\ud83d\u0041"}`:  "\xed\xa0\xbdA",
		`{"a":"\u00e9\/\t"}`:    "\xc3\xa9/\t",
		`{"a":"plain"}`:         "plain",
		`{"a":"a b"}`:           "a b",
	} {
		o, err := parseJSON([]byte(in))
		if err != nil || o["a"] != want {
			t.Errorf("%s: %q %v, want %q", in, o["a"], err, want)
		}
	}
	if o, err := parseJSON([]byte(`{"a":-1}`)); err != nil || o["a"] != -1.0 {
		t.Fatalf("negative: %v %v", o, err)
	}
	if !isCount(float64(1<<53-1), 0) || isCount(float64(1<<53), 0) || isCount(1.5, 0) || isCount(-1.0, 0) || isCount("1", 0) || isCount(math.Inf(1), 0) {
		t.Fatal("isCount")
	}
}
