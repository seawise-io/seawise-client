// Package devicecall sends device API calls signed with a DPoP proof by
// the device key: a fresh jti per attempt, the newest server nonce, one
// immediate retry when the server asks for its nonce, verified TLS only,
// no redirects and a bounded answer.
package devicecall

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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seawise/client/internal/protocol"
)

const (
	// MaxAnswer is the largest answer body read unless a call asks for more.
	MaxAnswer = 4 << 10
	// MaxLargeAnswer is the largest answer a call may ask for, such as an
	// app list.
	MaxLargeAnswer = 64 << 10
	// MaxRetryAfter caps a server's Retry-After.
	MaxRetryAfter = time.Hour
	unknownNonce  = "none"
)

var (
	ErrInsecureOrigin = errors.New("API origin must be an https origin")
	ErrInsecureTLS    = errors.New("HTTP client skips TLS verification")
	ErrAnswerTooLarge = errors.New("device API answer too large")
)

// Config wires a Caller.
type Config struct {
	Client  *http.Client
	Version string
	// Now is the proof's iat; the agent passes its signed-time clock.
	Now func() time.Time
	// JTI returns a proof id; nil uses 16 random bytes.
	JTI func() string
}

// Answer is a device API answer. NonceChallenge is set when the server
// still asks for its nonce after the one retry.
type Answer struct {
	Status         int
	Body           []byte
	RetryAfter     time.Duration
	NonceChallenge bool
}

// Request is one signed call. MaxAnswer 0 reads at most MaxAnswer bytes.
type Request struct {
	Key       crypto.Signer
	Origin    string
	Method    string
	Path      string
	Body      []byte
	Header    map[string]string
	MaxAnswer int
}

// Caller is safe for concurrent use; every user shares its nonce.
type Caller struct {
	client *http.Client
	ua     string
	now    func() time.Time
	jti    func() string

	mu    sync.Mutex
	nonce string
}

func New(cfg Config) (*Caller, error) {
	cl := http.Client{Timeout: 30 * time.Second}
	if cfg.Client != nil {
		cl = *cfg.Client
	}
	if t, ok := cl.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrInsecureTLS
	}
	// A redirect would carry the proof and any credential header elsewhere.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &Caller{client: &cl, ua: "seawise-agent/" + cfg.Version, now: cfg.Now, jti: cfg.JTI}
	if c.now == nil {
		c.now = time.Now
	}
	if c.jti == nil {
		c.jti = NewJTI
	}
	return c, nil
}

// NewJTI returns 16 random bytes, base64url.
func NewJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// CheckOrigin accepts only a bare https origin and returns it without a
// trailing slash.
func CheckOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInsecureOrigin
	}
	return "https://" + u.Host, nil
}

func (c *Caller) currentNonce() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nonce == "" {
		return unknownNonce
	}
	return c.nonce
}

// Nonce is the nonce the next proof carries ("none" before the first).
func (c *Caller) Nonce() string { return c.currentNonce() }

// KeepNonce stores a valid server nonce for the next proof.
func (c *Caller) KeepNonce(n string) {
	if !protocol.ValidNonce(n) {
		return
	}
	c.mu.Lock()
	c.nonce = n
	c.mu.Unlock()
}

// Do sends method path on origin with body, signed by key, retrying once
// at once when the server asks for its nonce. header is sent as well; it
// cannot replace the proof or the agent's own headers.
func (c *Caller) Do(ctx context.Context, key crypto.Signer, origin, method, path string, body []byte, header map[string]string) (Answer, error) {
	return c.Send(ctx, Request{Key: key, Origin: origin, Method: method, Path: path, Body: body, Header: header})
}

// Send is Do with the answer cap of r.
func (c *Caller) Send(ctx context.Context, r Request) (Answer, error) {
	if r.MaxAnswer == 0 {
		r.MaxAnswer = MaxAnswer
	}
	if r.MaxAnswer < 0 || r.MaxAnswer > MaxLargeAnswer {
		return Answer{}, errors.New("answer cap out of range")
	}
	var a Answer
	for attempt := 0; attempt < 2; attempt++ {
		var retry bool
		var err error
		a, retry, err = c.once(ctx, r)
		if err != nil || !retry {
			return a, err
		}
	}
	return a, nil
}

// Proof signs a proof for a call carried another way, such as stream 0:
// a fresh jti, the newest nonce and the clock of every other proof.
func (c *Caller) Proof(key crypto.Signer, method, url string, body []byte) (string, error) {
	if key == nil {
		return "", errors.New("sign proof: no device key")
	}
	p, err := protocol.NewDPoP(key, method, url, body, c.currentNonce(), c.jti(), c.now().Unix())
	if err != nil {
		return "", fmt.Errorf("sign proof: %w", err)
	}
	return p, nil
}

// Challenged reports an answer asking for the server's DPoP nonce.
func Challenged(status int, wwwAuthenticate string, body []byte) bool {
	return status == http.StatusUnauthorized &&
		(strings.Contains(wwwAuthenticate, "use_dpop_nonce") || ParseRefusal(body).Error == "use_dpop_nonce")
}

func (c *Caller) once(ctx context.Context, r Request) (Answer, bool, error) {
	u := r.Origin + r.Path
	proof, err := c.Proof(r.Key, r.Method, u, r.Body)
	if err != nil {
		return Answer{}, false, err
	}
	var rd io.Reader
	if r.Method != http.MethodGet {
		rd = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, u, rd)
	if err != nil {
		return Answer{}, false, err
	}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}
	req.Header.Set("DPoP", proof)
	req.Header.Set("User-Agent", c.ua)
	if r.Method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Del("Content-Type")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Answer{}, false, fmt.Errorf("device API unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(r.MaxAnswer)+1))
	if err != nil {
		return Answer{}, false, errors.New("device API answer cut short")
	}
	if len(raw) > r.MaxAnswer {
		return Answer{}, false, ErrAnswerTooLarge
	}
	n := resp.Header.Get("DPoP-Nonce")
	c.KeepNonce(n)
	a := Answer{Status: resp.StatusCode, Body: raw}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		a.RetryAfter = min(time.Duration(s)*time.Second, MaxRetryAfter)
	}
	a.NonceChallenge = Challenged(resp.StatusCode, resp.Header.Get("WWW-Authenticate"), raw)
	return a, a.NonceChallenge && protocol.ValidNonce(n), nil
}
