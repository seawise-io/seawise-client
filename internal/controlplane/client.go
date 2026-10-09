// Package controlplane is the agent's client for the SeaWise device API.
// It never follows redirects, parses replies strictly, and classifies every
// reply so callers can tell a transient failure from a removal report.
package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/seawise/client/internal/constants"
)

const (
	MaxBody            = 1 << 20
	MaxAttempts        = 3
	DefaultTimeout     = 15 * time.Second
	DefaultBackoffBase = 500 * time.Millisecond
	DefaultBackoffMax  = 5 * time.Second
	MaxRetryAfter      = 30 * time.Second
)

type Kind int

const (
	// Transient covers network errors, timeouts, redirects, 5xx, 429 and
	// malformed replies. Callers keep their current state.
	Transient Kind = iota + 1
	// Rejected is any other 4xx, including authentication failures.
	Rejected
	// Superseded is a heartbeat 409: another connection holds this server.
	Superseded
	// Removal is a heartbeat 410 carrying an unpair action. It is a report,
	// not an instruction; see RemovalTracker.
	Removal
)

func (k Kind) String() string {
	switch k {
	case Transient:
		return "transient"
	case Rejected:
		return "rejected"
	case Superseded:
		return "superseded"
	case Removal:
		return "removal"
	}
	return "unknown"
}

type Error struct {
	Op     string
	Status int
	Kind   Kind
	Reason string
	Err    error

	retryAfter time.Duration
	noRetry    bool
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(e.Kind.String())
	if e.Status != 0 {
		fmt.Fprintf(&b, " (status %d)", e.Status)
	}
	if e.Reason != "" {
		b.WriteString(": ")
		b.WriteString(e.Reason)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the kind of err; errors not produced by this package are
// transient.
func KindOf(err error) Kind {
	if err == nil {
		return 0
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Transient
}

type Config struct {
	BaseURL        string
	Token          func() string
	Version        string
	Timeout        time.Duration
	AllowedDomains []string
	// HTTPClient is for tests; its redirect policy is replaced.
	HTTPClient *http.Client
	Sleep      func(context.Context, time.Duration) error
}

type Client struct {
	base    string
	token   func() string
	ua      string
	timeout time.Duration
	domains []string
	http    *http.Client
	sleep   func(context.Context, time.Duration) error
}

func New(cfg Config) (*Client, error) {
	base, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Token == nil {
		return nil, errors.New("token source required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.AllowedDomains == nil {
		cfg.AllowedDomains = constants.AllowedFRPDomains
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}
	if cfg.Version == "" {
		cfg.Version = constants.Version
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          4,
			ForceAttemptHTTP2:     true,
		}}
	} else {
		c := *hc
		hc = &c
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		base: base, token: cfg.Token, ua: "seawise-agent/" + cfg.Version, timeout: cfg.Timeout,
		domains: cfg.AllowedDomains, http: hc, sleep: cfg.Sleep,
	}, nil
}

func validateBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("invalid API URL %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", fmt.Errorf("API URL %q must be a bare origin", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		switch strings.ToLower(u.Hostname()) {
		case "localhost", "127.0.0.1", "::1", constants.DockerHostInternal:
		default:
			return "", fmt.Errorf("API URL %q must use HTTPS", raw)
		}
	default:
		return "", fmt.Errorf("API URL %q must use HTTPS", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

type call struct {
	op         string
	method     string
	path       string
	body       any
	auth       bool
	idempotent bool
	write      bool
	heartbeat  bool
	expectData bool
}

// do runs c and returns the raw "data" member of a 2xx reply (nil when the
// call expects none).
func (c *Client) do(ctx context.Context, cl call) (json.RawMessage, error) {
	var payload []byte
	if cl.body != nil {
		b, err := json.Marshal(cl.body)
		if err != nil {
			return nil, &Error{Op: cl.op, Kind: Rejected, Err: err}
		}
		payload = b
	}
	tok := ""
	if cl.auth {
		if tok = c.token(); tok == "" {
			return nil, &Error{Op: cl.op, Kind: Rejected, Reason: "not paired"}
		}
	}
	key := ""
	if cl.write {
		key = newKey()
	}
	for attempt := 1; ; attempt++ {
		data, err := c.once(ctx, cl, payload, tok, key)
		if err == nil {
			return data, nil
		}
		var e *Error
		if !errors.As(err, &e) || e.Kind != Transient || !cl.idempotent || e.noRetry || attempt >= MaxAttempts || ctx.Err() != nil {
			return nil, err
		}
		wait := e.retryAfter
		if wait == 0 {
			wait = jitter(attempt)
		}
		if serr := c.sleep(ctx, wait); serr != nil {
			return nil, err
		}
	}
}

func (c *Client) once(ctx context.Context, cl call, payload []byte, tok, key string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, cl.method, c.base+cl.path, body)
	if err != nil {
		return nil, &Error{Op: cl.op, Kind: Rejected, Err: err}
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if tok != "" {
		req.Header.Set("X-FRP-Token", tok)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{Op: cl.op, Kind: Transient, Err: errors.Unwrap(err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
	if err != nil {
		return nil, &Error{Op: cl.op, Status: resp.StatusCode, Kind: Transient, Err: err}
	}
	if len(raw) > MaxBody {
		return nil, &Error{Op: cl.op, Status: resp.StatusCode, Kind: Transient, Reason: "reply too large"}
	}
	isJSON := jsonType(resp.Header.Get("Content-Type"))
	st := resp.StatusCode

	switch {
	case st >= 200 && st < 300:
		if !cl.expectData {
			return nil, nil
		}
		if !isJSON {
			return nil, &Error{Op: cl.op, Status: st, Kind: Transient, Reason: "reply is not JSON"}
		}
		env, err := decodeObject(raw)
		if err != nil {
			return nil, &Error{Op: cl.op, Status: st, Kind: Transient, Err: err}
		}
		data, ok := env["data"]
		if !ok {
			return nil, &Error{Op: cl.op, Status: st, Kind: Transient, Reason: "reply has no data"}
		}
		return data, nil
	case st >= 300 && st < 400:
		return nil, &Error{Op: cl.op, Status: st, Kind: Transient, Reason: "redirect not followed", noRetry: true}
	case st == http.StatusConflict && cl.heartbeat:
		return nil, &Error{Op: cl.op, Status: st, Kind: Superseded}
	case st == http.StatusGone:
		if !cl.heartbeat {
			return nil, &Error{Op: cl.op, Status: st, Kind: Rejected, Reason: errorText(raw, isJSON)}
		}
		if reason, ok := unpairBody(raw, isJSON); ok {
			return nil, &Error{Op: cl.op, Status: st, Kind: Removal, Reason: reason}
		}
		return nil, &Error{Op: cl.op, Status: st, Kind: Transient, Reason: "410 without an unpair body"}
	case st == http.StatusTooManyRequests:
		e := &Error{Op: cl.op, Status: st, Kind: Transient}
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && n >= 0 {
				d := time.Duration(n) * time.Second
				if d > MaxRetryAfter {
					e.noRetry = true
				} else {
					e.retryAfter = d
				}
			}
		}
		return nil, e
	case st >= 500:
		return nil, &Error{Op: cl.op, Status: st, Kind: Transient}
	default:
		return nil, &Error{Op: cl.op, Status: st, Kind: Rejected, Reason: errorText(raw, isJSON)}
	}
}

func jsonType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json"
}

// decodeObject requires exactly one JSON object and nothing after it.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("reply is not an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after reply")
	}
	return m, nil
}

func unpairBody(raw []byte, isJSON bool) (string, bool) {
	if !isJSON {
		return "", false
	}
	m, err := decodeObject(raw)
	if err != nil {
		return "", false
	}
	var action, reason string
	if json.Unmarshal(m["action"], &action) != nil || action != "unpair" {
		return "", false
	}
	_ = json.Unmarshal(m["reason"], &reason)
	if reason = clean(reason, 64); reason == "" {
		reason = "unspecified"
	}
	return reason, true
}

func errorText(raw []byte, isJSON bool) string {
	if !isJSON {
		return ""
	}
	m, err := decodeObject(raw)
	if err != nil {
		return ""
	}
	var s string
	_ = json.Unmarshal(m["error"], &s)
	return clean(s, 200)
}

// clean keeps printable characters and truncates, so server text is safe
// to log and show.
func clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func jitter(attempt int) time.Duration {
	d := DefaultBackoffBase << (attempt - 1)
	if d > DefaultBackoffMax || d <= 0 {
		d = DefaultBackoffMax
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)+1))
	if err != nil {
		return d
	}
	return time.Duration(n.Int64())
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
