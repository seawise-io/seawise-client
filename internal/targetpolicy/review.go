package targetpolicy

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/seawise/client/internal/store"
)

// Resolver returns the addresses a host name resolves to.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// ReviewItem is one row of the local review screen.
type ReviewItem struct {
	LocalID       string     `json:"local_id"`
	Name          string     `json:"name"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	Disabled      bool       `json:"disabled"`
	Grandfathered bool       `json:"grandfathered"`
	ConfirmedAt   *time.Time `json:"confirmed_at,omitempty"`
	Granted       []string   `json:"granted"`
	// ServerDisableRequestedAt is set while the server asks to turn the app
	// off; the app keeps running until the owner accepts.
	ServerDisableRequestedAt *time.Time `json:"server_disable_requested_at,omitempty"`
	Assessment
	// Missing lists required grants the target does not hold. The agent does
	// not tunnel a target while its literal address misses a grant, and the
	// forwarder refuses connections to addresses that miss one.
	Missing []string `json:"missing"`
}

// ResolveHost resolves a target host, returning a literal address as is.
func ResolveHost(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	h := strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(h); err == nil {
		return []netip.Addr{a}, nil
	}
	return r(ctx, h)
}

// BuildReview lists targets that are grandfathered, disabled, have a pending
// server disable request, or whose current addresses need grants they do
// not hold. publicAllowed is the operator opt-in for public targets.
func BuildReview(ctx context.Context, targets []store.Target, resolve Resolver, gateways []netip.Addr, publicAllowed bool) []ReviewItem {
	out := []ReviewItem{}
	for _, t := range targets {
		var as Assessment
		addrs, err := ResolveHost(ctx, resolve, t.Host)
		if err != nil {
			as = Assessment{Classes: []Class{}, Required: []string{}, Refused: "host did not resolve"}
		} else {
			as = Assess(t.Host, t.Port, addrs, gateways, Options{PublicAllowed: publicAllowed})
		}
		granted := append([]string{}, t.Allowed...)
		if t.Grandfathered {
			granted = append(granted, grandfatheredGrants...)
		}
		missing := []string{}
		for _, g := range as.Required {
			if !slices.Contains(granted, g) {
				missing = append(missing, g)
			}
		}
		if !t.Grandfathered && !t.Disabled && t.ServerDisableRequestedAt == nil && len(missing) == 0 && as.Refused == "" {
			continue
		}
		out = append(out, ReviewItem{
			LocalID: t.LocalID, Name: t.Name, Host: t.Host, Port: t.Port, Disabled: t.Disabled,
			Grandfathered: t.Grandfathered, ConfirmedAt: t.ConfirmedAt, Granted: granted, Assessment: as, Missing: missing,
			ServerDisableRequestedAt: t.ServerDisableRequestedAt,
		})
	}
	return out
}

var (
	ErrNotFound = errors.New("target not found")
	ErrChanged  = errors.New("target changed while it was being reviewed")
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

// Confirm records the owner's review: the target keeps exactly the grants
// its current addresses need and stops being grandfathered. host and port
// are the values that were assessed; a target that changed since is not
// confirmed.
func Confirm(st *store.State, localID, host string, port int, as Assessment, now time.Time) error {
	if as.Refused != "" {
		return errors.New("target cannot be confirmed: " + as.Refused)
	}
	t := find(st, localID)
	if t == nil {
		return ErrNotFound
	}
	if t.Host != host || t.Port != port {
		return ErrChanged
	}
	t.Allowed = append([]string(nil), as.Required...)
	t.Grandfathered = false
	at := now
	t.ConfirmedAt = &at
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
