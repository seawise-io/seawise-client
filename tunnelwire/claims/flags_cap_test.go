package claims

import (
	"fmt"
	"testing"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"
)

// The largest valid flags document, both lists full and every number at
// its widest, fits the flags cap and parses.
func TestLargestFlagsFitCap(t *testing.T) {
	salt := fx.Bytes("cap-salt", SaltSize)
	list := func(from, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = HashedID(salt, fx.Bytes(fmt.Sprintf("srv-%d", from+i), 16))
		}
		return out
	}
	c := map[string]any{"generation": int64(1)<<53 - 1, "global": "off", "rollout_permille": 1000, "salt": vkeys.B64(salt),
		"allow": list(0, MaxFlagsList), "deny": list(MaxFlagsList, MaxFlagsList), "iat": int64(1)<<53 - 1}
	tok := vkeys.SignJWS(vkeys.Key(controlK), TypFlags, c)
	if len(tok) > wire.MaxFlags || CheckFlagsSize(tok) != nil {
		t.Fatalf("largest document is %d bytes, cap %d", len(tok), wire.MaxFlags)
	}
	if _, err := ParseFlags(vkeys.JSON(c)); err != nil {
		t.Fatal(err)
	}
}
