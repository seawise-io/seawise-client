package session

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"
)

// PollEvery is the interface poll interval where netlink is not available.
const PollEvery = 15 * time.Second

// WatchNetwork signals address, link and route changes. Signals coalesce:
// the channel holds at most one.
func WatchNetwork(ctx context.Context, log *slog.Logger) <-chan struct{} {
	ch := make(chan struct{}, 1)
	if !watchNetlink(ctx, ch, log) {
		go pollInterfaces(ctx, ch, PollEvery, interfaceFingerprint)
	}
	return ch
}

func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func pollInterfaces(ctx context.Context, ch chan<- struct{}, every time.Duration, fp func() string) {
	last := fp()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if cur := fp(); cur != last {
				last = cur
				notify(ch)
			}
		}
	}
}

// interfaceFingerprint lists the up interfaces with their addresses.
func interfaceFingerprint() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			out = append(out, i.Name+"="+a.String())
		}
		out = append(out, i.Name)
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}
