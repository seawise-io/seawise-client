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
	Assessment
	// Missing lists required grants the target does not hold; a reviewed
	// target with missing grants would be refused at dial time.
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

// BuildReview lists targets that are grandfathered, or whose current
// addresses need grants they do not hold. Grandfathered targets are
// assessed as if public targets were allowed, because they already work.
func BuildReview(ctx context.Context, targets []store.Target, resolve Resolver, gateways []netip.Addr) []ReviewItem {
	out := []ReviewItem{}
	for _, t := range targets {
		var as Assessment
		addrs, err := ResolveHost(ctx, resolve, t.Host)
		if err != nil {
			as = Assessment{Classes: []Class{}, Required: []string{}, Refused: "host did not resolve"}
		} else {
			as = Assess(t.Host, t.Port, addrs, gateways, Options{PublicAllowed: true})
		}
		missing := []string{}
		for _, g := range as.Required {
			if !slices.Contains(t.Allowed, g) {
				missing = append(missing, g)
			}
		}
		if !t.Grandfathered && len(missing) == 0 && as.Refused == "" {
			continue
		}
		granted := append([]string{}, t.Allowed...)
		if t.Grandfathered {
			granted = append([]string{}, allGrants...)
		}
		out = append(out, ReviewItem{
			LocalID: t.LocalID, Name: t.Name, Host: t.Host, Port: t.Port, Disabled: t.Disabled,
			Grandfathered: t.Grandfathered, ConfirmedAt: t.ConfirmedAt, Granted: granted, Assessment: as, Missing: missing,
		})
	}
	return out
}

var ErrNotFound = errors.New("target not found")

// Confirm records the owner's review: the target keeps exactly the grants
// its current addresses need and stops being grandfathered.
func Confirm(st *store.State, localID string, as Assessment, now time.Time) error {
	if as.Refused != "" {
		return errors.New("target cannot be confirmed: " + as.Refused)
	}
	for i := range st.Targets {
		t := &st.Targets[i]
		if t.LocalID != localID {
			continue
		}
		t.Allowed = append([]string(nil), as.Required...)
		t.Grandfathered = false
		at := now
		t.ConfirmedAt = &at
		return nil
	}
	return ErrNotFound
}

// Disable turns a target off without deleting it.
func Disable(st *store.State, localID string) error {
	for i := range st.Targets {
		if st.Targets[i].LocalID == localID {
			st.Targets[i].Disabled = true
			return nil
		}
	}
	return ErrNotFound
}
