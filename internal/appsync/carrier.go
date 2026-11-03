package appsync

import (
	"context"

	"github.com/seawise/client/internal/devapi"
)

// ErrAnswerTooLarge is an answer over 64 KiB.
var ErrAnswerTooLarge = devapi.ErrAnswerTooLarge

// Request is one device call. Key is the Idempotency-Key, empty for calls
// that are not queued.
type Request = devapi.Call

// Response is the device API's answer. Relayed answers came over stream 0
// and never remove a local app; a direct list confirms them.
type Response = devapi.Answer

// Carrier delivers device calls, on stream 0 or over HTTPS. An error means
// the outcome is unknown and the call is retried as is.
type Carrier interface {
	Do(ctx context.Context, r Request) (Response, error)
}
