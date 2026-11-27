package session

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/devicecall"
)

// HeartbeatPath is the signed heartbeat; SIGNED_TIME is its stream 0 twin.
const HeartbeatPath = "/device/v2/heartbeat"

const (
	maxAnswer = devicecall.MaxLargeAnswer
	// unknownNonce makes the server answer use_dpop_nonce with a fresh one.
	unknownNonce = "none"
)

// ErrUnsigned is a heartbeat answer without a signed state.
var ErrUnsigned = errors.New("heartbeat answer carries no signed state")

// Heartbeat sends the signed heartbeat: a DPoP-proved request whose answer
// carries the control-key signed device state and the protocol flags.
type Heartbeat struct {
	// Origin is the control plane origin, such as https://api.seawise.io.
	Origin string
	Key    func() crypto.Signer
	// Caller signs and sends the heartbeat. The agent shares one with its
	// other device calls, so every proof uses the newest server nonce. nil
	// builds one from Client, Version and Now.
	Caller  *devicecall.Caller
	Client  *http.Client
	Version string
	Now     func() time.Time

	once sync.Once
	call *devicecall.Caller
	err  error
}

// Answer is the signed part of a heartbeat answer.
type Answer struct {
	State string // sw-state+jwt
	Flags string // sw-tunnel-flags+jws, "" when none
}

func (h *Heartbeat) caller() (*devicecall.Caller, error) {
	h.once.Do(func() {
		if h.call = h.Caller; h.call == nil {
			h.call, h.err = devicecall.New(devicecall.Config{Client: h.Client, Version: h.Version, Now: h.Now})
		}
	})
	return h.call, h.err
}

func (h *Heartbeat) origin() string { return strings.TrimSuffix(h.Origin, "/") }

func (h *Heartbeat) dpopNonce() string {
	c, err := h.caller()
	if err != nil {
		return unknownNonce
	}
	return c.Nonce()
}

func requestBody(nonce string, connected bool, version string) []byte {
	b, _ := json.Marshal(struct {
		Nonce         string `json:"nonce"`
		FRPConnected  bool   `json:"frp_connected"`
		ClientVersion string `json:"client_version,omitempty"`
	}{nonce, connected, version})
	return b
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Heartbeat) key() crypto.Signer {
	if h.Key == nil {
		return nil
	}
	return h.Key()
}

// HTTPS sends the heartbeat over HTTPS, retrying once with a server nonce.
func (h *Heartbeat) HTTPS(ctx context.Context, nonce string, connected bool) (Answer, error) {
	return h.HTTPSAs(ctx, h.key(), nonce, connected)
}

// HTTPSAs sends the heartbeat proved by key, such as a pending rotation
// key, whose signed state then names that key.
func (h *Heartbeat) HTTPSAs(ctx context.Context, key crypto.Signer, nonce string, connected bool) (Answer, error) {
	c, err := h.caller()
	if err != nil {
		return Answer{}, err
	}
	if key == nil {
		return Answer{}, errors.New("no device key")
	}
	a, err := c.Send(ctx, devicecall.Request{Key: key, Origin: h.origin(), Method: http.MethodPost, Path: HeartbeatPath,
		Body: requestBody(nonce, connected, h.Version), MaxAnswer: maxAnswer})
	if err != nil {
		return Answer{}, err
	}
	if a.Status != http.StatusOK {
		return Answer{}, fmt.Errorf("heartbeat: status %d", a.Status)
	}
	return parseAnswer(a.Body)
}

// Call builds the stream 0 twin of the heartbeat. The idempotency key is
// reused for a nonce retry of the same call.
func (h *Heartbeat) Call(callID uint32, key []byte, nonce string, connected bool) (*pb.DeviceCall, error) {
	c, err := h.caller()
	if err != nil {
		return nil, err
	}
	body := requestBody(nonce, connected, h.Version)
	p, err := c.Proof(h.key(), http.MethodPost, h.origin()+HeartbeatPath, body)
	if err != nil {
		return nil, err
	}
	return &pb.DeviceCall{CallId: callID, IdempotencyKey: key, Method: pb.DeviceMethod_SIGNED_TIME, Dpop: p, Body: body}, nil
}

// Result reads a DeviceResult of the stream 0 call: the answer, or retry
// when the server asked for its nonce.
func (h *Heartbeat) Result(r *pb.DeviceResult) (Answer, bool, error) {
	if r.GetClass() != pb.ResultClass_DONE {
		return Answer{}, false, errors.New("heartbeat call: outcome unknown")
	}
	if c, err := h.caller(); err == nil {
		c.KeepNonce(r.GetDpopNonce())
	}
	switch {
	case r.GetHttpStatus() == http.StatusUnauthorized && r.GetDpopNonce() != "":
		return Answer{}, true, nil
	case r.GetHttpStatus() != http.StatusOK:
		return Answer{}, false, fmt.Errorf("heartbeat call: status %d", r.GetHttpStatus())
	}
	a, err := parseAnswer(r.GetBody())
	return a, false, err
}

// parseAnswer takes data.signed_time (required) and data.flags (string or
// null) from {"data":{...}}.
func parseAnswer(raw []byte) (Answer, error) {
	var top struct {
		Data *struct {
			SignedTime *string          `json:"signed_time"`
			Flags      *json.RawMessage `json:"flags"`
		} `json:"data"`
	}
	if len(raw) > maxAnswer || json.Unmarshal(raw, &top) != nil || top.Data == nil {
		return Answer{}, errors.New("heartbeat: malformed answer")
	}
	if top.Data.SignedTime == nil || *top.Data.SignedTime == "" {
		return Answer{}, ErrUnsigned
	}
	a := Answer{State: *top.Data.SignedTime}
	if f := top.Data.Flags; f != nil && string(*f) != "null" {
		if err := json.Unmarshal(*f, &a.Flags); err != nil {
			return Answer{}, errors.New("heartbeat: malformed flags")
		}
	}
	return a, nil
}
