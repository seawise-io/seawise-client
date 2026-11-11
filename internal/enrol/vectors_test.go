package enrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/devicecall"
)

type vecFile struct {
	Format string `json:"format"`
	Keys   []struct {
		Name string `json:"name"`
		Seed string `json:"seed"`
		KID  string `json:"kid"`
	} `json:"keys"`
	Cases []struct {
		Name  string `json:"name"`
		Input struct {
			DPoP     string  `json:"dpop"`
			FRPToken *string `json:"frp_token"`
			Body     string  `json:"body"`
		} `json:"input"`
		Context struct {
			Method   string `json:"method"`
			URL      string `json:"url"`
			NowMS    int64  `json:"now_ms"`
			NonceKey string `json:"nonce_key"`
			Server   struct {
				ID          string `json:"id"`
				TokenSHA256 string `json:"token_sha256"`
			} `json:"server"`
			RegisteredKIDs []string `json:"registered_kids"`
			Seen           []struct {
				KID string `json:"kid"`
				JTI string `json:"jti"`
			} `json:"seen"`
		} `json:"context"`
		Expect string `json:"expect"`
		Wire   struct {
			Status int `json:"status"`
			Body   any `json:"body"`
		} `json:"wire"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vecFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "enrol.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f vecFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Format != "enrol" || len(f.Cases) == 0 {
		t.Fatal("not an enrol vector file")
	}
	return f
}

func TestVectorsThroughFake(t *testing.T) {
	f := loadVectors(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			cx := c.Context
			key, err := hex.DecodeString(cx.NonceKey)
			if err != nil {
				t.Fatal(err)
			}
			fk := newFake(cx.Server.ID, "")
			fk.tokenHash, fk.nonceKey = cx.Server.TokenSHA256, key
			fk.now = func() time.Time { return time.UnixMilli(cx.NowMS) }
			u := cx.URL[:strings.Index(cx.URL, "/device/")]
			fk.publicURL = u
			for _, k := range cx.RegisteredKIDs {
				fk.registered[k] = true
			}
			for _, s := range cx.Seen {
				fk.seen[s.KID+":"+s.JTI] = true
			}
			req := httptest.NewRequest(cx.Method, cx.URL, strings.NewReader(c.Input.Body))
			req.Header.Set("DPoP", c.Input.DPoP)
			if c.Input.FRPToken != nil {
				req.Header.Set("X-FRP-Token", *c.Input.FRPToken)
			}
			rec := httptest.NewRecorder()
			fk.ServeHTTP(rec, req)
			if rec.Code != c.Wire.Status {
				t.Fatalf("status %d, want %d (%s)", rec.Code, c.Wire.Status, rec.Body)
			}
			var got any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.Wire.Body) {
				t.Fatalf("body %v, want %v", got, c.Wire.Body)
			}
			if rec.Header().Get("DPoP-Nonce") == "" {
				t.Fatal("answer without a nonce")
			}
			if wantClass := classify(PathEnroll, c.Wire.Status, rec.Body.Bytes()); c.Wire.Status != 200 && wantClass.kind == kindOK {
				t.Fatal("refusal classified as success")
			}
		})
	}
}

type captureRT struct {
	req  *http.Request
	body []byte
}

func (c *captureRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	c.body, _ = io.ReadAll(r.Body)
	return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
}

// The client's enrol request equals the valid vectors byte for byte.
func TestRequestMatchesVectors(t *testing.T) {
	f := loadVectors(t)
	var seed []byte
	for _, k := range f.Keys {
		if k.Name == "enrol-new" {
			seed, _ = hex.DecodeString(k.Seed)
		}
	}
	priv := ed25519.NewKeyFromSeed(seed)
	for _, c := range f.Cases {
		if c.Name != "valid" {
			continue
		}
		var claims struct {
			JTI   string `json:"jti"`
			IAT   int64  `json:"iat"`
			Nonce string `json:"nonce"`
		}
		payload := strings.Split(c.Input.DPoP, ".")[1]
		b, err := b64(payload)
		if err != nil || json.Unmarshal(b, &claims) != nil {
			t.Fatal("vector proof payload")
		}
		rt := &captureRT{}
		cl, err := devicecall.New(devicecall.Config{Client: &http.Client{Transport: rt}, Version: "test", Now: func() time.Time { return time.Unix(claims.IAT, 0) }, JTI: func() string { return claims.JTI }})
		if err != nil {
			t.Fatal(err)
		}
		cl.KeepNonce(claims.Nonce)
		origin := c.Context.URL[:strings.Index(c.Context.URL, PathEnroll)]
		body := serverIDBody(c.Context.Server.ID)
		if _, err := cl.Do(context.Background(), priv, origin, http.MethodPost, PathEnroll, body, map[string]string{frpTokenHeader: *c.Input.FRPToken}); err != nil {
			t.Fatal(err)
		}
		if got := rt.req.Header.Get("DPoP"); got != c.Input.DPoP {
			t.Fatalf("proof differs from the vector:\n%s\n%s", got, c.Input.DPoP)
		}
		if !bytes.Equal(rt.body, []byte(c.Input.Body)) || rt.req.Header.Get("X-FRP-Token") != *c.Input.FRPToken || rt.req.URL.String() != c.Context.URL {
			t.Fatal("request differs from the vector")
		}
		return
	}
	t.Fatal("no valid case")
}
