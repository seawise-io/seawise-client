// Package devapi sends the agent's device API calls: on stream 0 of the
// tunnel session while one is up, over HTTPS otherwise. Both carriers send
// the same request (the HTTPS twin's method, path and body, a DPoP proof
// for that twin, the same idempotency key) and give the same answers, so
// callers never see which one carried a call, apart from Answer.Relayed.
package devapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
	"github.com/seawise-io/seawise-client/tunnelwire/wire"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/protocol"
)

var (
	// ErrAnswerTooLarge is an answer over devicecall.MaxLargeAnswer.
	ErrAnswerTooLarge = devicecall.ErrAnswerTooLarge
	// ErrNoKey means the device has no key to prove a call with.
	ErrNoKey = errors.New("device call: no device key")

	errUnavailable = errors.New("device call on stream 0: outcome unknown")
)

// Call is one device API call.
type Call struct {
	Method pb.DeviceMethod
	// Key is the idempotency key, 32 lower-case hex, the same on every
	// attempt and on both carriers; "" for calls that are not queued.
	Key  string
	Body []byte
	// Direct sends the call over HTTPS only, so its answer comes straight
	// from the device API.
	Direct bool
}

// Answer is the device API's answer. NonceChallenge is set when the
// server still asks for its nonce after one retry with it.
type Answer struct {
	Status         int
	Body           []byte
	RetryAfter     time.Duration
	NonceChallenge bool
	// Relayed is set for an answer carried on stream 0. The edge relays it
	// unchanged but is not the device API's TLS, so an answer that would
	// remove local state must be confirmed by a Direct call.
	Relayed bool
}

// Relay carries a device call on stream 0 of the active, verified session
// and returns its result. An error means the call was not answered there.
type Relay interface {
	Relay(ctx context.Context, call *pb.DeviceCall) (*pb.DeviceResult, error)
}

type Config struct {
	// Caller signs every proof and sends the HTTPS calls; one per agent,
	// so every call uses the newest server nonce.
	Caller *devicecall.Caller
	// Origin is the device API origin, an https origin; proofs on both
	// carriers name the HTTPS twin under it.
	Origin func() string
	Key    func() crypto.Signer
	// Stream0 carries calls while a session is up; nil sends every call
	// over HTTPS.
	Stream0 Relay
	Logger  *slog.Logger
}

// Client is safe for concurrent use.
type Client struct {
	cfg Config
	log *slog.Logger
}

func New(cfg Config) (*Client, error) {
	if cfg.Caller == nil || cfg.Origin == nil || cfg.Key == nil {
		return nil, errors.New("devapi: caller, origin and key are required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{cfg: cfg, log: log}, nil
}

// ValidKey reports whether k is an idempotency key: 32 lower-case hex.
func ValidKey(k string) bool {
	if len(k) != 32 {
		return false
	}
	for _, c := range k {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Do sends the call on stream 0 when a session is up and the body fits,
// else over HTTPS. A stream 0 attempt whose outcome is unknown (no result,
// UNAVAILABLE, the session lost) is sent again over HTTPS under the same
// key, which the device API dedupes. An error means the outcome is
// unknown; the caller retries the same call later.
func (c *Client) Do(ctx context.Context, call Call) (Answer, error) {
	route, ok := wire.DeviceRoutes[call.Method]
	if !ok || route.Param {
		return Answer{}, fmt.Errorf("device call: unknown method %d", call.Method)
	}
	if call.Key != "" && !ValidKey(call.Key) {
		return Answer{}, errors.New("device call: malformed idempotency key")
	}
	origin, err := devicecall.CheckOrigin(c.cfg.Origin())
	if err != nil {
		return Answer{}, err
	}
	key := c.cfg.Key()
	if key == nil {
		return Answer{}, ErrNoKey
	}
	if !call.Direct && c.cfg.Stream0 != nil && len(call.Body) <= wire.MaxDeviceBody {
		a, err := c.relayWithin(ctx, call, route, origin, key)
		if err == nil {
			return a, nil
		}
		if ctx.Err() != nil {
			return Answer{}, err
		}
		c.log.Debug("device call not answered on stream 0; sending over HTTPS", "method", call.Method.String(), "error", err)
	}
	var header map[string]string
	if call.Key != "" {
		header = map[string]string{"Idempotency-Key": call.Key}
	}
	a, err := c.cfg.Caller.Send(ctx, devicecall.Request{Key: key, Origin: origin, Method: route.Method, Path: route.Path,
		Body: call.Body, Header: header, MaxAnswer: devicecall.MaxLargeAnswer})
	if err != nil {
		return Answer{}, err
	}
	return Answer{Status: a.Status, Body: a.Body, RetryAfter: a.RetryAfter, NonceChallenge: a.NonceChallenge}, nil
}

// relayWithin gives the stream 0 attempt at most half of the time left, so
// the HTTPS resend still has time when it gets no result.
func (c *Client) relayWithin(ctx context.Context, call Call, route wire.DeviceRoute, origin string, key crypto.Signer) (Answer, error) {
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Until(dl)/2)
		defer cancel()
	}
	return c.relay(ctx, call, route, origin, key)
}

func (c *Client) relay(ctx context.Context, call Call, route wire.DeviceRoute, origin string, key crypto.Signer) (Answer, error) {
	idem := make([]byte, 16)
	if call.Key != "" {
		_, _ = hex.Decode(idem, []byte(call.Key))
	} else {
		_, _ = rand.Read(idem)
	}
	var a Answer
	for attempt := 0; attempt < 2; attempt++ {
		proof, err := c.cfg.Caller.Proof(key, route.Method, origin+route.Path, call.Body)
		if err != nil {
			return Answer{}, err
		}
		r, err := c.cfg.Stream0.Relay(ctx, &pb.DeviceCall{IdempotencyKey: idem, Method: call.Method, Dpop: proof, Body: call.Body})
		if err != nil {
			return Answer{}, err
		}
		if r.GetClass() != pb.ResultClass_DONE {
			return Answer{}, errUnavailable
		}
		c.cfg.Caller.KeepNonce(r.GetDpopNonce())
		a = Answer{Status: int(r.GetHttpStatus()), Body: r.GetBody(), Relayed: true,
			RetryAfter: min(time.Duration(r.GetRetryAfterMs())*time.Millisecond, devicecall.MaxRetryAfter)}
		a.NonceChallenge = devicecall.Challenged(a.Status, "", a.Body)
		if !a.NonceChallenge || !protocol.ValidNonce(r.GetDpopNonce()) {
			break
		}
	}
	return a, nil
}
