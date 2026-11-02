package session

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestPollSignalsChanges(t *testing.T) {
	var mu sync.Mutex
	fp := "a"
	ch := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollInterfaces(ctx, ch, 5*time.Millisecond, func() string { mu.Lock(); defer mu.Unlock(); return fp })
	select {
	case <-ch:
		t.Fatal("signal without a change")
	case <-time.After(30 * time.Millisecond):
	}
	mu.Lock()
	fp = "b"
	mu.Unlock()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("change not signalled")
	}
}

func TestNotifyCoalesces(t *testing.T) {
	ch := make(chan struct{}, 1)
	notify(ch)
	notify(ch)
	<-ch
	select {
	case <-ch:
		t.Fatal("second signal kept")
	default:
	}
}

func TestWatchNetworkStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	if WatchNetwork(ctx, slog.New(slog.DiscardHandler)) == nil {
		t.Fatal("nil channel")
	}
	cancel()
	if interfaceFingerprint() == "" {
		t.Skip("no interfaces visible")
	}
}
