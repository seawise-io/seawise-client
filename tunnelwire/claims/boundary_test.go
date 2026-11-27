package claims

import (
	"encoding/base64"
	"strings"
	"testing"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

func nested(depth int) []byte {
	return []byte(`{"a":` + strings.Repeat(`{"a":`, depth-1) + "1" + strings.Repeat("}", depth))
}

func TestDepthLimit(t *testing.T) {
	var v map[string]any
	if err := decodeObject(nested(maxDepth), &v, []string{"a"}); err != nil {
		t.Fatalf("depth %d refused: %v", maxDepth, err)
	}
	if err := decodeObject(nested(maxDepth+1), &v, []string{"a"}); CodeOf(err) != CodeMalformed {
		t.Fatalf("depth %d accepted", maxDepth+1)
	}
	arr := []byte(`{"a":` + strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth) + "}")
	if err := decodeObject(arr, &v, []string{"a"}); CodeOf(err) != CodeMalformed {
		t.Fatal("deep arrays accepted")
	}
	arr = []byte(`{"a":` + strings.Repeat("[", maxDepth-1) + strings.Repeat("]", maxDepth-1) + "}")
	if err := decodeObject(arr, &v, []string{"a"}); err != nil {
		t.Fatal("arrays at the limit refused", err)
	}
}

func TestFQDNBounds(t *testing.T) {
	l := fx.Repeat("a", 63)
	max := l + "." + l + "." + l + "." + fx.Repeat("b", 61)
	if len(max) != MaxFQDN || !ValidFQDN(max) || ValidFQDN(max+"b") {
		t.Fatal("253 bound")
	}
	for _, s := range []string{"a.-b", "a.b-", "a..b", ".a", "a.", "a.B", ""} {
		if ValidFQDN(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestVersionAndGenerationOne(t *testing.T) {
	c := rsClaims(func(c map[string]any) { c["version"] = 1 })
	e := RouteSetExpect{EdgeID: fx.EdgeA, Signer: fx.EdgeA, ServerID: fx.Server1, SessionID: sessionID()}
	if _, err := CheckRouteSet(vkeys.JSON(c), e); err != nil {
		t.Fatal("routeset version 1", err)
	}
	f := map[string]any{"generation": 1, "global": "on", "rollout_permille": 0, "salt": base64.RawURLEncoding.EncodeToString(fx.Bytes("s", 16)), "allow": []string{}, "deny": []string{}, "iat": 0}
	if _, err := ParseFlags(vkeys.JSON(f)); err != nil {
		t.Fatal("flags generation 1", err)
	}
}
