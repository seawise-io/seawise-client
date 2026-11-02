package targetpolicy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/seawise/client/internal/store"
)

// Resolver returns the addresses a host name resolves to.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// ReviewItem is one row of the local review list. The list is
// informational: what an app reaches, apps that are turned off, and
// requests from SeaWise to turn an app off. Only a refused address stops
// an app.
type ReviewItem struct {
	LocalID  string `json:"local_id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Disabled bool   `json:"disabled"`
	// ServerDisableRequestedAt is set while the server asks to turn the app
	// off; the app keeps running until the owner accepts.
	ServerDisableRequestedAt *time.Time `json:"server_disable_requested_at,omitempty"`
	Assessment
}

// ResolveHost resolves a target host, returning a literal address as is.
func ResolveHost(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	h := strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(h); err == nil {
		return []netip.Addr{a}, nil
	}
	return r(ctx, h)
}

// BuildReview lists the targets that are turned off, have a pending server
// disable request, reach an address that is refused, or reach a class of
// address worth pointing out (this machine, a public address, a mail port,
// a management API port or the network gateway).
func BuildReview(ctx context.Context, targets []store.Target, resolve Resolver, gateways []netip.Addr) []ReviewItem {
	out := []ReviewItem{}
	for _, t := range targets {
		var as Assessment
		addrs, err := ResolveHost(ctx, resolve, t.Host)
		if err != nil {
			as = Assessment{Classes: []Class{}, Required: []string{}, Refused: "host did not resolve"}
		} else {
			as = Assess(t.Host, t.Port, addrs, gateways)
		}
		if !t.Disabled && t.ServerDisableRequestedAt == nil && len(as.Required) == 0 && as.Refused == "" {
			continue
		}
		out = append(out, ReviewItem{
			LocalID: t.LocalID, Name: t.Name, Host: t.Host, Port: t.Port, Disabled: t.Disabled,
			ServerDisableRequestedAt: t.ServerDisableRequestedAt, Assessment: as,
		})
	}
	return out
}

var (
	ErrNotFound = errors.New("target not found")
	ErrNoAction = errors.New("nothing to do for this target")
)

func find(st *store.State, localID string) *store.Target {
	for i := range st.Targets {
		if st.Targets[i].LocalID == localID {
			return &st.Targets[i]
		}
	}
	return nil
}

// Disable turns a target off without deleting it; it also settles any
// pending server request.
func Disable(st *store.State, localID string) error {
	t := find(st, localID)
	if t == nil {
		return ErrNotFound
	}
	t.Disabled = true
	t.ServerDisableRequestedAt = nil
	return nil
}

func Enable(st *store.State, localID string) error {
	t := find(st, localID)
	if t == nil {
		return ErrNotFound
	}
	t.Disabled = false
	return nil
}

// AcceptServerDisable turns the app off at the server's pending request.
func AcceptServerDisable(st *store.State, localID string) error {
	t := find(st, localID)
	if t == nil {
		return ErrNotFound
	}
	if t.ServerDisableRequestedAt == nil {
		return ErrNoAction
	}
	return Disable(st, localID)
}

// DismissServerDisable keeps the app running and drops the request.
func DismissServerDisable(st *store.State, localID string) error {
	t := find(st, localID)
	if t == nil {
		return ErrNotFound
	}
	if t.ServerDisableRequestedAt == nil {
		return ErrNoAction
	}
	t.ServerDisableRequestedAt = nil
	return nil
}
