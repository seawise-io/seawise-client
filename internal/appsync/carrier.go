package appsync

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/protocol"
)

const maxAnswer = 64 << 10

// ErrAnswerTooLarge is an answer over maxAnswer.
var ErrAnswerTooLarge = errors.New("device call: answer over 64 KiB")

// Request is one device call. Key is the Idempotency-Key, empty for calls
// that are not queued.
type Request struct {
	Method pb.DeviceMethod
	Key    string
	Body   []byte
}

// Response is the server's answer. NonceChallenge is set when the server
// asked for a proof with its nonce.
type Response struct {
	Status         int
	Body           []byte
	NonceChallenge bool
	RetryAfter     time.Duration
}

// Carrier delivers device calls: over HTTPS, or over the tunnel's stream
// 0. An error means the outcome is unknown and the call is retried as is.
type Carrier interface {
	Do(ctx context.Context, r Request) (Response, error)
	// Authenticated reports whether answers come straight from the device
	// API over TLS. Only such answers may remove local apps; a relayed
	// carrier (stream 0) returns false and its deleted answers are only
	// reported.
	Authenticated() bool
}

// HTTPS sends device calls to the device API with a fresh DPoP proof per
// attempt, signed with the newest nonce.
type HTTPS struct {
	Origin  string
	Key     func() crypto.Signer
	Client  *http.Client
	Version string
	Now     func() time.Time

	mu    sync.Mutex
	nonce string
}

func (h *HTTPS) currentNonce() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.nonce == "" {
		return "none"
	}
	return h.nonce
}

func (h *HTTPS) keepNonce(n string) {
	if !protocol.ValidNonce(n) {
		return
	}
	h.mu.Lock()
	h.nonce = n
	h.mu.Unlock()
}

func (h *HTTPS) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func jti() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *HTTPS) Authenticated() bool { return true }

func (h *HTTPS) Do(ctx context.Context, r Request) (Response, error) {
	method, path, err := wire.TwinPath(r.Method, "")
	if err != nil {
		return Response{}, fmt.Errorf("device call: %w", err)
	}
	var key crypto.Signer
	if h.Key != nil {
		key = h.Key()
	}
	if key == nil {
		return Response{}, errors.New("device call: no device key")
	}
	url := strings.TrimSuffix(h.Origin, "/") + path
	proof, err := protocol.NewDPoP(key, method, url, r.Body, h.currentNonce(), jti(), h.now().Unix())
	if err != nil {
		return Response{}, err
	}
	var body io.Reader
	if method != http.MethodGet {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("DPoP", proof)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.Key != "" {
		req.Header.Set("Idempotency-Key", r.Key)
	}
	req.Header.Set("User-Agent", "seawise-agent/"+h.Version)
	c := http.Client{Timeout: 30 * time.Second}
	if h.Client != nil {
		c = *h.Client
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return Response{}, err
	}
	if len(raw) > maxAnswer {
		return Response{}, ErrAnswerTooLarge
	}
	n := resp.Header.Get("DPoP-Nonce")
	h.keepNonce(n)
	out := Response{Status: resp.StatusCode, Body: raw}
	if resp.StatusCode == http.StatusUnauthorized {
		out.NonceChallenge = strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") || parseError(raw).Error == "use_dpop_nonce"
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		out.RetryAfter = time.Duration(min(s, 3600)) * time.Second
	}
	return out, nil
}
