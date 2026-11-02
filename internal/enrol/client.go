package enrol

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
	maxAnswer     = 4 << 10
	unknownNonce  = "none"
	maxRetryAfter = time.Hour
)

var (
	errInsecureOrigin = errors.New("API origin must be an https origin")
	errInsecureTLS    = errors.New("HTTP client skips TLS verification")
)

type answer struct {
	status     int
	body       []byte
	retryAfter time.Duration
}

// caller sends device calls with a fresh proof per attempt and keeps the
// newest server nonce.
type caller struct {
	client *http.Client
	ua     string
	now    func() time.Time
	jti    func() string

	mu    sync.Mutex
	nonce string
}

func newCaller(c *http.Client, version string, now func() time.Time) (*caller, error) {
	cl := http.Client{Timeout: 30 * time.Second}
	if c != nil {
		cl = *c
	}
	if t, ok := cl.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return nil, errInsecureTLS
	}
	// A redirect would carry X-FRP-Token to wherever it points.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &caller{client: &cl, ua: "seawise-agent/" + version, now: now, jti: newJTI}, nil
}

func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// checkOrigin accepts only a bare https origin.
func checkOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", errInsecureOrigin
	}
	return "https://" + u.Host, nil
}

func (c *caller) currentNonce() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nonce == "" {
		return unknownNonce
	}
	return c.nonce
}

func (c *caller) keepNonce(n string) {
	if !protocol.ValidNonce(n) {
		return
	}
	c.mu.Lock()
	c.nonce = n
	c.mu.Unlock()
}

// do sends one call, retrying once at once when the server asks for its
// nonce. token is sent only when path is the enrol path.
func (c *caller) do(ctx context.Context, key crypto.Signer, origin, method, path string, body []byte, token string) (answer, error) {
	if token != "" && path != PathEnroll {
		return answer{}, errors.New("frp token on a call other than enrol")
	}
	var a answer
	for attempt := 0; attempt < 2; attempt++ {
		var challenged bool
		var err error
		a, challenged, err = c.once(ctx, key, origin, method, path, body, token)
		if err != nil || !challenged {
			return a, err
		}
	}
	return a, nil
}

func (c *caller) once(ctx context.Context, key crypto.Signer, origin, method, path string, body []byte, token string) (answer, bool, error) {
	u := origin + path
	proof, err := protocol.NewDPoP(key, method, u, body, c.currentNonce(), c.jti(), c.now().Unix())
	if err != nil {
		return answer{}, false, fmt.Errorf("sign proof: %w", err)
	}
	var rd io.Reader
	if method != http.MethodGet {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return answer{}, false, err
	}
	req.Header.Set("DPoP", proof)
	req.Header.Set("User-Agent", c.ua)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-FRP-Token", token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return answer{}, false, fmt.Errorf("device API unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return answer{}, false, errors.New("device API answer cut short")
	}
	if len(raw) > maxAnswer {
		return answer{}, false, errors.New("device API answer too large")
	}
	n := resp.Header.Get("DPoP-Nonce")
	c.keepNonce(n)
	a := answer{status: resp.StatusCode, body: raw}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		a.retryAfter = min(time.Duration(s)*time.Second, maxRetryAfter)
	}
	challenged := resp.StatusCode == http.StatusUnauthorized && protocol.ValidNonce(n) &&
		(strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") || parseRefusal(raw).Error == "use_dpop_nonce")
	return a, challenged, nil
}

// serverIDBody is the body of enrol and confirm.
func serverIDBody(serverID string) []byte {
	return []byte(`{"server_id":"` + serverID + `"}`)
}
