// Package healthprobe checks whether each tunnelled app accepts TCP
// connections and reports every app's status each round.
package healthprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/seawise/client/internal/store"
	"github.com/seawise/client/internal/targetpolicy"
)

const (
	DefaultStartDelay = 10 * time.Second
	DefaultInterval   = 30 * time.Second
	DefaultTimeout    = 3 * time.Second
	DefaultCheckEvery = 5 * time.Second
	DefaultWorkers    = 8
	// FreshRounds rounds after the tunnel comes up are reported as fresh.
	FreshRounds = 2
)

const (
	Online  = "online"
	Offline = "offline"
)

type Config struct {
	// Targets returns the stored apps; enabled apps with a subdomain are
	// probed and disabled apps are reported offline.
	Targets func() []store.Target
	// Report receives the status of every stored app each round. fresh is
	// set for the first FreshRounds rounds after the tunnel comes up, when
	// the server may have reset what it knew.
	Report func(statuses map[string]string, fresh bool)
	// Connected reports whether the tunnel is up; nil means always.
	Connected func() bool
	Gateways  []netip.Addr
	Resolve   targetpolicy.Resolver
	Dialer    *net.Dialer

	StartDelay time.Duration
	Interval   time.Duration
	Timeout    time.Duration
	// CheckEvery is how often the tunnel state is checked.
	CheckEvery time.Duration
	Workers    int
}

type Prober struct {
	cfg Config
}

func New(cfg Config) (*Prober, error) {
	if cfg.Targets == nil || cfg.Report == nil {
		return nil, errors.New("healthprobe: targets and report required")
	}
	if cfg.Connected == nil {
		cfg.Connected = func() bool { return true }
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if cfg.Dialer == nil {
		cfg.Dialer = &net.Dialer{}
	}
	cfg.StartDelay = orDefault(cfg.StartDelay, DefaultStartDelay)
	cfg.Interval = orDefault(cfg.Interval, DefaultInterval)
	cfg.Timeout = orDefault(cfg.Timeout, DefaultTimeout)
	cfg.CheckEvery = orDefault(cfg.CheckEvery, DefaultCheckEvery)
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	return &Prober{cfg: cfg}, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Run probes every Interval while the tunnel is up, and right after the
// tunnel comes back.
func (p *Prober) Run(ctx context.Context) {
	if !sleep(ctx, p.cfg.StartDelay) {
		return
	}
	up := false
	rounds := 0
	var due time.Time
	for {
		if p.cfg.Connected() {
			if !up || !time.Now().Before(due) {
				if !up {
					rounds = 0
				}
				up = true
				due = time.Now().Add(p.cfg.Interval)
				p.round(ctx, rounds < FreshRounds)
				rounds++
			}
		} else {
			up = false
		}
		if !sleep(ctx, p.cfg.CheckEvery) {
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (p *Prober) round(ctx context.Context, fresh bool) {
	all := p.cfg.Targets()
	got := make(map[string]string, len(all))
	var apps []store.Target
	for _, t := range all {
		if t.Disabled {
			got[t.LocalID] = Offline
		} else if t.Subdomain != "" && t.Port >= 1 && t.Port <= 65535 {
			apps = append(apps, t)
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.cfg.Workers)
	for _, t := range apps {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := p.probe(ctx, t)
			mu.Lock()
			got[t.LocalID] = s
			mu.Unlock()
			<-sem
		}()
	}
	wg.Wait()
	if ctx.Err() != nil || len(got) == 0 {
		return
	}
	p.cfg.Report(got, fresh)
}

// probe connects the way the forwarder does: through the target policy,
// trying each resolved address, so a refused address is never connected to.
func (p *Prober) probe(ctx context.Context, t store.Target) string {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	addrs, err := targetpolicy.ResolveHost(ctx, p.cfg.Resolve, t.Host)
	if err != nil {
		return Offline
	}
	base := *p.cfg.Dialer
	base.Timeout = p.cfg.Timeout
	d := targetpolicy.Dialer(&base, targetpolicy.RuleFor(t), p.cfg.Gateways)
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.Unmap().String(), strconv.Itoa(t.Port)))
		if err == nil {
			_ = c.Close()
			return Online
		}
	}
	return Offline
}
