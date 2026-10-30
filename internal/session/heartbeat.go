package session

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/protocol"
)

// HeartbeatPath is the signed heartbeat; SIGNED_TIME is its stream 0 twin.
const HeartbeatPath = "/device/v2/heartbeat"

const (
	maxAnswer = 64 << 10
	// unknownNonce makes the server answer use_dpop_nonce with a fresh one.
	unknownNonce = "none"
)

// ErrUnsigned is a heartbeat answer without a signed state.
var ErrUnsigned = errors.New("heartbeat answer carries no signed state")

// Heartbeat sends the signed heartbeat: a DPoP-proved request whose answer
// carries the control-key signed device state and the protocol flags.
type Heartbeat struct {
	// Origin is the control plane origin, such as https://api.seawise.io.
	Origin  string
	Key     func() crypto.Signer
	Client  *http.Client
	Version string
	Now     func() time.Time

	mu    sync.Mutex
	nonce string // newest DPoP-Nonce seen
}

// Answer is the signed part of a heartbeat answer.
type Answer struct {
	State string // sw-state+jwt
	Flags string // sw-tunnel-flags+jws, "" when none
}

func (h *Heartbeat) url() string { return strings.TrimSuffix(h.Origin, "/") + HeartbeatPath }

func (h *Heartbeat) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Heartbeat) dpopNonce() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nonce == "" {
		return unknownNonce
	}
	return h.nonce
}

func (h *Heartbeat) keepNonce(n string) {
	if !protocol.ValidNonce(n) {
		return
	}
	h.mu.Lock()
	h.nonce = n
	h.mu.Unlock()
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

func (h *Heartbeat) proof(key crypto.Signer, body []byte) (string, error) {
	if key == nil {
		return "", errors.New("no device key")
	}
	return protocol.NewDPoP(key, http.MethodPost, h.url(), body, h.dpopNonce(), newID(), h.now().Unix())
}

// HTTPS sends the heartbeat over HTTPS, retrying once with a server nonce.
func (h *Heartbeat) HTTPS(ctx context.Context, nonce string, connected bool) (Answer, error) {
	return h.HTTPSAs(ctx, h.key(), nonce, connected)
}

// HTTPSAs sends the heartbeat proved by key, such as a pending rotation
// key, whose signed state then names that key.
func (h *Heartbeat) HTTPSAs(ctx context.Context, key crypto.Signer, nonce string, connected bool) (Answer, error) {
	body := requestBody(nonce, connected, h.Version)
	for attempt := 0; ; attempt++ {
		status, raw, retry, err := h.post(ctx, key, body)
		if err != nil {
			return Answer{}, err
		}
		if status == http.StatusUnauthorized && retry && attempt == 0 {
			continue
		}
		if status != http.StatusOK {
			return Answer{}, fmt.Errorf("heartbeat: status %d", status)
		}
		return parseAnswer(raw)
	}
}

func (h *Heartbeat) post(ctx context.Context, key crypto.Signer, body []byte) (int, []byte, bool, error) {
	p, err := h.proof(key, body)
	if err != nil {
		return 0, nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", p)
	c := h.Client
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, false, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return 0, nil, false, err
	}
	if len(raw) > maxAnswer {
		return 0, nil, false, errors.New("heartbeat: answer too large")
	}
	n := resp.Header.Get("DPoP-Nonce")
	h.keepNonce(n)
	retry := n != "" && strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce")
	return resp.StatusCode, raw, retry, nil
}

// Call builds the stream 0 twin of the heartbeat. The idempotency key is
// reused for a nonce retry of the same call.
func (h *Heartbeat) Call(callID uint32, key []byte, nonce string, connected bool) (*pb.DeviceCall, error) {
	body := requestBody(nonce, connected, h.Version)
	p, err := h.proof(h.key(), body)
	if err != nil {
		return nil, err
	}
	return &pb.DeviceCall{CallId: callID, IdempotencyKey: key, Method: pb.DeviceMethod_SIGNED_TIME, Dpop: p, Body: body}, nil
}

// Result reads a DeviceResult of the stream 0 call: the answer, or retry
// when the server asked for its nonce.
func (h *Heartbeat) Result(r *pb.DeviceResult) (Answer, bool, error) {
	h.keepNonce(r.GetDpopNonce())
	if r.GetClass() != pb.ResultClass_DONE {
		return Answer{}, false, errors.New("heartbeat call: outcome unknown")
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
