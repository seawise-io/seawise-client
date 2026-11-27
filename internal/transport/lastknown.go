package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

// Last-known edge addresses, used only when DNS fails.
const (
	LastKnownFile = "tunnel-edges.json"
	// LastKnownMaxAge bounds how old a stored address may be.
	LastKnownMaxAge   = 7 * 24 * time.Hour
	lastKnownSkew     = 5 * time.Minute
	lastKnownRefresh  = time.Hour
	lastKnownMaxNames = 8
	lastKnownMaxAddrs = 4
)

type lastKnownFile struct {
	Schema int                       `json:"schema"`
	Edges  map[string]lastKnownEntry `json:"edges"`
}

type lastKnownEntry struct {
	Addrs      []string  `json:"addrs"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// lastKnown keeps the last good addresses per tunnel name in one file.
type lastKnown struct {
	path string
	now  func() time.Time
	log  *slog.Logger
	mu   sync.Mutex
}

func (c *lastKnown) load() lastKnownFile {
	empty := lastKnownFile{Schema: 1, Edges: map[string]lastKnownEntry{}}
	b, err := store.ReadOwned(c.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.log.Warn("last-known edge addresses not used", "error", err)
		}
		return empty
	}
	var f lastKnownFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Schema != 1 || len(f.Edges) > lastKnownMaxNames {
		c.log.Warn("last-known edge addresses unreadable; ignoring them")
		return empty
	}
	for _, e := range f.Edges {
		if len(e.Addrs) == 0 || len(e.Addrs) > lastKnownMaxAddrs || len(usable(parseAddrs(e.Addrs))) != len(e.Addrs) {
			c.log.Warn("last-known edge addresses invalid; ignoring them")
			return empty
		}
	}
	return f
}

// lookup returns the stored addresses for name, IPv4 first, if fresh.
func (c *lastKnown) lookup(name string) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.load().Edges[name]
	if !ok {
		return nil, false
	}
	age := c.now().Sub(e.ResolvedAt)
	if age < -lastKnownSkew || age >= LastKnownMaxAge {
		return nil, false
	}
	addrs := parseAddrs(e.Addrs)
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() && !b.Is4():
			return -1
		case b.Is4() && !a.Is4():
			return 1
		}
		return 0
	})
	return addrs, len(addrs) > 0
}

// remember stores the public addresses of a successful lookup.
func (c *lastKnown) remember(name string, resolved []netip.Addr) {
	addrs := usable(resolved)
	if len(addrs) == 0 {
		return
	}
	strs := make([]string, len(addrs))
	for i, a := range addrs {
		strs[i] = a.String()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.load()
	now := c.now().UTC()
	if e, ok := f.Edges[name]; ok && slices.Equal(e.Addrs, strs) && now.Sub(e.ResolvedAt) < lastKnownRefresh && now.Sub(e.ResolvedAt) >= 0 {
		return
	}
	f.Edges[name] = lastKnownEntry{Addrs: strs, ResolvedAt: now}
	for len(f.Edges) > lastKnownMaxNames {
		oldest := ""
		for n, e := range f.Edges {
			if oldest == "" || e.ResolvedAt.Before(f.Edges[oldest].ResolvedAt) {
				oldest = n
			}
		}
		delete(f.Edges, oldest)
	}
	b, err := json.Marshal(f)
	if err == nil {
		err = store.WriteFileAtomic(c.path, b, 0o600)
	}
	if err != nil && !errors.Is(err, store.ErrNotDurable) {
		c.log.Warn("store last-known edge addresses", "error", err)
	}
}

func newLastKnown(dir string, now func() time.Time, log *slog.Logger) *lastKnown {
	if dir == "" {
		return nil
	}
	return &lastKnown{path: filepath.Join(dir, LastKnownFile), now: now, log: log}
}

func parseAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// usable keeps public unicast addresses, at most four, without duplicates.
func usable(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if c, _ := targetpolicy.Classify(a); c != targetpolicy.Public || a.Zone() != "" || slices.Contains(out, a) {
			continue
		}
		out = append(out, a)
		if len(out) == lastKnownMaxAddrs {
			break
		}
	}
	return out
}
