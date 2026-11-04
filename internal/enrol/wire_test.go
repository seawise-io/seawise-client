package enrol

import (
	"strings"
	"testing"

	"github.com/seawise/client/internal/store"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		path   string
		status int
		body   string
		kind   kind
		hold   string
	}{
		{PathEnroll, 401, `{"error":"invalid_token"}`, kindHold, store.HoldInvalidToken},
		{PathEnroll, 409, `{"error":"already_enrolled"}`, kindHold, store.HoldAlreadyEnrolled},
		{PathEnroll, 400, `{"error":"invalid_key","code":"bad_key"}`, kindHold, store.HoldBadKey},
		{PathEnroll, 403, `{"error":"repair_required"}`, kindHold, store.HoldRepairRequired},
		{PathEnroll, 400, `{"error":"invalid_request","code":"malformed"}`, kindHold, store.HoldInvalidRequest},
		{PathEnroll, 401, `{"error":"invalid_proof","code":"replayed"}`, kindRetry, ""},
		{PathEnroll, 401, `{"error":"invalid_proof","code":"key_revoked"}`, kindRetry, ""},
		{PathEnroll, 401, `{"error":"invalid_proof","code":"invalid_proof"}`, kindRetry, ""},
		{PathEnroll, 401, `{"error":"use_dpop_nonce","code":"use_dpop_nonce"}`, kindRetry, ""},
		{PathEnroll, 409, `{"error":"not_enrolled"}`, kindRetry, ""},
		{PathEnroll, 429, `{"error":"Too many"}`, kindRetry, ""},
		{PathEnroll, 503, `{"error":"Service unavailable"}`, kindRetry, ""},
		{PathEnroll, 500, ``, kindRetry, ""},
		{PathEnroll, 404, `{"error":"invalid_token"}`, kindRetry, ""},
		{PathEnroll, 401, `not json`, kindRetry, ""},
		{PathEnroll, 418, `{}`, kindRetry, ""},
		{PathIdentity, 401, `{"error":"invalid_proof","code":"key_revoked"}`, kindHold, store.HoldKeyRevoked},
		{PathIdentity, 401, `{"error":"invalid_proof","code":"invalid_proof"}`, kindUnknownKey, ""},
		{PathIdentity, 401, `{"error":"invalid_proof","code":"replayed"}`, kindRetry, ""},
		{PathIdentity, 401, `{"error":"invalid_token"}`, kindRetry, ""},
		{PathIdentity, 409, `{"error":"not_enrolled"}`, kindRetry, ""},
		{PathConfirm, 409, `{"error":"not_enrolled"}`, kindHold, store.HoldNotEnrolled},
		{PathConfirm, 400, `{"error":"invalid_request","code":"wrong_server"}`, kindHold, store.HoldSwitchRefused},
		{PathConfirm, 401, `{"error":"invalid_proof","code":"key_revoked"}`, kindHold, store.HoldKeyRevoked},
		{PathConfirm, 401, `{"error":"invalid_proof","code":"invalid_proof"}`, kindUnknownKey, ""},
		{PathConfirm, 401, `{"error":"invalid_token"}`, kindRetry, ""},
		{PathConfirm, 409, `{"error":"already_enrolled"}`, kindRetry, ""},
		{PathConfirm, 503, `{"error":"not_enrolled"}`, kindRetry, ""},
	}
	for _, c := range cases {
		o := classify(c.path, c.status, []byte(c.body))
		if o.kind != c.kind || o.hold != c.hold {
			t.Errorf("%s %d %s: got %+v", c.path, c.status, c.body, o)
		}
		if o.kind == kindRetry && o.reason == "" {
			t.Errorf("%s %d: retry without a reason", c.path, c.status)
		}
	}
}

func TestValidToken(t *testing.T) {
	if !validToken(testToken) {
		t.Fatal("hex token refused")
	}
	for _, s := range []string{"", testToken[:63], testToken + "0", strings.ToUpper(testToken), strings.Repeat("g", 64), strings.Repeat("/", 64), strings.Repeat(":", 64), strings.Repeat("`", 64)} {
		if validToken(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func FuzzClassify(f *testing.F) {
	f.Add(PathEnroll, 401, []byte(`{"error":"invalid_proof","code":"key_revoked"}`))
	f.Add(PathConfirm, 409, []byte(`{"error":"not_enrolled"}`))
	f.Add(PathIdentity, 503, []byte(`x`))
	f.Fuzz(func(t *testing.T, path string, status int, body []byte) {
		o := classify(path, status, body)
		switch o.kind {
		case kindRetry:
			if o.reason == "" || strings.ContainsAny(o.reason, "\n\r") {
				t.Fatal("retry reason")
			}
		case kindHold:
			if !holdKnown(o.hold) {
				t.Fatal("unknown hold")
			}
			if status >= 500 || status == 429 || status == 404 {
				t.Fatal("outage read as a refusal")
			}
		case kindUnknownKey:
			if path == PathEnroll {
				t.Fatal("unknown key on enrol")
			}
		default:
			t.Fatal("non-200 answer read as success")
		}
		if path == PathEnroll && o.hold == store.HoldKeyRevoked {
			t.Fatal("enrol hold for a revoked key")
		}
	})
}

func holdKnown(h string) bool { _, ok := holdText[h]; return ok }
