package claims

import (
	"crypto/ed25519"
	"testing"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

// The signer emits the state with its own typ and its claims sorted by
// name. Signing those exact bytes with the vector seed gives the vector
// token; the same claims with v1_token_live, without key_id, or under the
// time typ are refused.
func TestSignedStateServerFormat(t *testing.T) {
	const n = "dGltZS1ub25jZS0wMDAwMDE"
	kid := vkeys.KID(fx.DeviceA)
	claims := `"account_status":"active","device_status":"revoked","key_id":"` + kid + `","nonce":"` + n + `","server_id":"` + fx.Server1 + `","time":1793000000`
	header := `{"typ":"sw-state+jwt","alg":"EdDSA","kid":"` + vkeys.KID(controlK) + `"}`
	tok := vkeys.SignRaw(vkeys.Key(controlK), header, "{"+claims+"}")
	var want string
	for _, c := range load(t, "signed_state.json").Cases {
		if c.Name == "revoked-under-right-nonce" {
			want = c.Input
		}
	}
	if tok != want {
		t.Fatalf("server-format token differs from the vector:\n%s\n%s", tok, want)
	}
	st, err := CheckSignedState([]byte("{"+claims+"}"), fx.Server1, kid, n)
	if err != nil || !st.Holds() || st.KeyID != kid {
		t.Fatal(st, err)
	}
	if _, err := CheckSignedState([]byte("{"+claims+`,"v1_token_live":false}`), fx.Server1, kid, n); CodeOf(err) != CodeMalformed {
		t.Fatal("v1_token_live accepted", err)
	}
	if _, err := CheckSignedState([]byte("{"+claims+"}"), fx.Server1, vkeys.KID(fx.DeviceB), n); CodeOf(err) != CodeWrongKey {
		t.Fatal("another key's state accepted", err)
	}
	if _, _, err := vkeys.VerifyJWS(vkeys.SignRaw(vkeys.Key(controlK), `{"typ":"sw-time+jwt","alg":"EdDSA","kid":"`+vkeys.KID(controlK)+`"}`, "{"+claims+"}"), TypState, map[string]ed25519.PublicKey{"control-1": vkeys.Pub(controlK)}); err == nil {
		t.Fatal("time typ read as state")
	}
	if TypState == TypTime {
		t.Fatal("state shares the time typ")
	}
}
