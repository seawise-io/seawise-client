package claims

import (
	"testing"

	fx "github.com/seawise-io/seawise-client/tunnelwire/internal/fixtures"
	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

func FuzzRouteSet(f *testing.F) {
	f.Add(vkeys.JSON(rsClaims(nil)))
	f.Add([]byte(`{"edge":1}`))
	e := RouteSetExpect{EdgeID: fx.EdgeA, Signer: fx.EdgeA, ServerID: fx.Server1, SessionID: sessionID()}
	f.Fuzz(func(t *testing.T, p []byte) {
		rs, err := CheckRouteSet(p, e)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatal("uncoded")
			}
			return
		}
		if len(rs.Routes) > MaxRoutes || rs.Version < 1 || rs.ServerID != fx.Server1 || rs.Edge != fx.EdgeA {
			t.Fatal("accepted a bad routeset")
		}
	})
}

func FuzzFlags(f *testing.F) {
	f.Add(vkeys.JSON(map[string]any{"generation": 7, "global": "on", "rollout_permille": 10, "salt": vkeys.B64(fx.Bytes("s", 16)), "allow": []string{}, "deny": []string{}, "iat": 1}))
	f.Fuzz(func(t *testing.T, p []byte) {
		fl, err := ParseFlags(p)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatal("uncoded")
			}
			return
		}
		m := fl.Mode(fx.UUID(fx.Server1))
		if (fl.Global == "off") != (m.String() == "OFF") {
			t.Fatal("mode does not follow global")
		}
	})
}

func FuzzSignedState(f *testing.F) {
	n, kid := "dGltZS1ub25jZS0wMDAwMDE", vkeys.KID(fx.DeviceA)
	f.Add(vkeys.JSON(map[string]any{"server_id": fx.Server1, "key_id": kid, "time": 1, "nonce": n, "device_status": "revoked", "account_status": "active"}))
	f.Add(vkeys.JSON(map[string]any{"server_id": fx.Server1, "time": 1, "nonce": n}))
	f.Fuzz(func(t *testing.T, p []byte) {
		st, err := CheckSignedState(p, fx.Server1, kid, n)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatal("uncoded")
			}
		} else if st.Nonce != n || st.ServerID != fx.Server1 || st.KeyID != kid || st.DeviceStatus == "" || st.AccountStatus == "" {
			t.Fatal("accepted a bad state")
		}
		tm, err := CheckSignedTime(p, fx.Server1, n)
		if err != nil {
			if CodeOf(err) == "" {
				t.Fatal("uncoded")
			}
		} else if tm.Nonce != n || tm.ServerID != fx.Server1 {
			t.Fatal("accepted a bad time")
		}
	})
}
