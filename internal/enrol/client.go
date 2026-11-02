package enrol

import (
	"context"
	"crypto"
	"errors"

	"github.com/seawise/client/internal/devicecall"
)

const frpTokenHeader = "X-FRP-Token"

// do sends one device call; the 1.x token goes only on the enrol call.
func (e *Enroller) do(ctx context.Context, key crypto.Signer, origin, method, path string, body []byte, token string) (devicecall.Answer, error) {
	if token == "" {
		return e.call.Do(ctx, key, origin, method, path, body, nil)
	}
	if path != PathEnroll {
		return devicecall.Answer{}, errors.New("frp token on a call other than enrol")
	}
	return e.call.Do(ctx, key, origin, method, path, body, map[string]string{frpTokenHeader: token})
}

// serverIDBody is the body of enrol and confirm.
func serverIDBody(serverID string) []byte {
	return []byte(`{"server_id":"` + serverID + `"}`)
}
