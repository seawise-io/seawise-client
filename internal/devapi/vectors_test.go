package devapi

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/seawise-io/seawise-client/tunnelwire/claims"
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"google.golang.org/protobuf/proto"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
)

type capture struct{ call *pb.DeviceCall }

func (c *capture) Relay(_ context.Context, call *pb.DeviceCall) (*pb.DeviceResult, error) {
	c.call = call
	return &pb.DeviceResult{CallId: 1, Class: pb.ResultClass_DONE, HttpStatus: 200}, nil
}

// Every call the agent sends on stream 0 passes the relayed-proof checks
// of the shared vectors: the twin's method and URL under the API origin,
// the body digest, the device's key and the server nonce.
func TestCallsPassTheRelayedProofVectors(t *testing.T) {
	raw, err := os.ReadFile("../../tunnelwire/testdata/vectors/device_call.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys []struct {
			Name, Seed, Kid string
		}
		Cases []struct {
			Name, Kind, Input, Expect string
			Context                   map[string]any
		}
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(f.Keys[0].Seed)
	key := ed25519.NewKeyFromSeed(seed)
	n := 0
	for _, c := range f.Cases {
		if c.Kind != "relayed_call" || !strings.HasPrefix(c.Name, "valid-") {
			continue
		}
		n++
		b, _ := base64.StdEncoding.DecodeString(c.Input)
		var in pb.DeviceCall
		if err := proto.Unmarshal(b, &in); err != nil {
			t.Fatal(err)
		}
		origin, nonce := c.Context["origin"].(string), c.Context["nonce"].(string)
		caller, err := devicecall.New(devicecall.Config{})
		if err != nil {
			t.Fatal(err)
		}
		caller.KeepNonce(nonce)
		cp := &capture{}
		cl, err := New(Config{Caller: caller, Origin: func() string { return origin }, Key: func() crypto.Signer { return key }, Stream0: cp})
		if err != nil {
			t.Fatal(err)
		}
		k := ""
		if in.GetMethod() == pb.DeviceMethod_REGISTER_APPS || in.GetMethod() == pb.DeviceMethod_DELETE_APPS {
			k = hex.EncodeToString(in.GetIdempotencyKey())
		}
		if _, err := cl.Do(context.Background(), Call{Method: in.GetMethod(), Key: k, Body: in.GetBody()}); err != nil {
			t.Fatal(c.Name, err)
		}
		parts := strings.Split(cp.call.GetDpop(), ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		dc, err := claims.ParseDPoPClaims(payload)
		if err != nil {
			t.Fatal(c.Name, err)
		}
		pub := key.Public().(ed25519.PublicKey)
		if err := claims.CheckRelayedProof(cp.call, origin, protocol.KeyID(pub), c.Context["server_kid"].(string), dc, nonce); err != nil {
			t.Fatal(c.Name, err)
		}
		if k != "" && hex.EncodeToString(cp.call.GetIdempotencyKey()) != k {
			t.Fatal(c.Name, "key")
		}
	}
	if n != 6 {
		t.Fatalf("%d valid cases", n)
	}
}
