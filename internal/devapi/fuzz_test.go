package devapi

import (
	"bytes"
	"context"
	"crypto"
	"testing"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
)

type fixedRelay struct{ r *pb.DeviceResult }

func (f fixedRelay) Relay(context.Context, *pb.DeviceCall) (*pb.DeviceResult, error) { return f.r, nil }

// Whatever result comes back on stream 0, DONE is the device API's answer
// passed through unchanged and anything else goes over HTTPS.
func FuzzRelayedResult(f *testing.F) {
	f.Add(uint8(1), uint32(200), []byte(`{}`), "", uint32(0))
	f.Add(uint8(1), uint32(401), []byte(`{"error":"use_dpop_nonce"}`), "n1.AAAAAQ.c2VydmVyLW5vbmNl", uint32(0))
	f.Add(uint8(2), uint32(0), []byte(nil), "", uint32(1000))
	f.Add(uint8(1), uint32(503), []byte(`{"error":"x"}`), "bad nonce", uint32(300000))
	f.Add(uint8(0), uint32(200), []byte(`{}`), "", uint32(4294967295))
	e := newEnv(f)
	f.Fuzz(func(t *testing.T, class uint8, status uint32, body []byte, nonce string, retry uint32) {
		r := &pb.DeviceResult{CallId: 1, Class: pb.ResultClass(class), HttpStatus: status, Body: body, DpopNonce: nonce, RetryAfterMs: retry}
		c, err := New(Config{Caller: e.caller, Origin: e.api.origin, Key: func() crypto.Signer { return deviceKey }, Stream0: fixedRelay{r}})
		if err != nil {
			t.Fatal(err)
		}
		a, err := c.Do(context.Background(), Call{Method: pb.DeviceMethod_REGISTER_APPS, Key: key1, Body: []byte(`{"apps":[]}`)})
		if err != nil {
			t.Fatal(err)
		}
		if a.RetryAfter < 0 || a.RetryAfter > devicecall.MaxRetryAfter {
			t.Fatal("retry after out of range", a.RetryAfter)
		}
		if r.GetClass() != pb.ResultClass_DONE {
			if a.Relayed || a.Status != 200 {
				t.Fatalf("UNAVAILABLE did not fall back: %+v", a)
			}
			return
		}
		if !a.Relayed || a.Status != int(status) || !bytes.Equal(a.Body, body) {
			t.Fatalf("DONE changed: %+v", a)
		}
		if a.NonceChallenge != devicecall.Challenged(int(status), "", body) {
			t.Fatal("challenge mark")
		}
		if protocol.ValidNonce(nonce) && e.caller.Nonce() != nonce {
			t.Fatal("valid relayed nonce not kept")
		}
	})
}
