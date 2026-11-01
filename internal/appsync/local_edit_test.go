package appsync

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/store"
)

func TestAddErrorsAreTyped(t *testing.T) {
	h := newHarness(t, app("Media", "10.0.0.1", 80))
	if _, err := h.e.Add("a\nb", "h", 1); !errors.Is(err, ErrInvalidApp) {
		t.Fatalf("invalid: %v", err)
	}
	for _, n := range []string{"Media", "mEDIA"} {
		if _, err := h.e.Add(n, "10.0.0.2", 81); !errors.Is(err, ErrNameExists) {
			t.Fatalf("duplicate %s: %v", n, err)
		}
	}
	err := h.st.Update(func(s *store.State) error {
		for len(s.Targets) < store.MaxTargets {
			s.Targets = append(s.Targets, app("x"+NewLocalID(), "10.0.0.3", 80))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.e.Add("More", "10.0.0.4", 80); !errors.Is(err, ErrTooManyApps) {
		t.Fatalf("cap: %v", err)
	}
}

func TestAddedAppRegisteredAndRemovedAppDeleted(t *testing.T) {
	h := newHarness(t)
	h.settle(20)
	id, err := h.e.Add("Wiki", "192.168.1.21", 8080)
	if err != nil {
		t.Fatal(err)
	}
	h.settle(20)
	if apps := registeredOn(t, h.api, 1); apps[0].LocalID != id {
		t.Fatalf("server %+v", apps)
	}
	if err := h.e.Remove(id); err != nil {
		t.Fatal(err)
	}
	if len(h.e.box.Calls) != 1 || h.e.box.Calls[0].Op != OpDelete || h.target(id) != nil {
		t.Fatalf("outbox %+v targets %+v", h.e.box.Calls, h.targets())
	}
	h.settle(20)
	registeredOn(t, h.api, 0)
}

func TestRemoveErrorsAreTyped(t *testing.T) {
	h := newHarness(t)
	if err := h.e.Remove(NewLocalID()); !errors.Is(err, ErrNoSuchApp) {
		t.Fatalf("missing: %v", err)
	}
	a := app("A", "10.0.0.1", 80)
	h = newHarness(t, a)
	h.settle(20)
	h.e.mu.Lock()
	for len(h.e.box.Calls) < MaxCalls {
		c, _ := registerCall([]RegisterItem{{LocalID: NewLocalID(), Name: "q", Host: "h", Port: 1}}, false, h.clk.Now())
		h.e.box.Calls = append(h.e.box.Calls, c)
	}
	h.e.mu.Unlock()
	if err := h.e.Remove(a.LocalID); !errors.Is(err, ErrOutboxFull) {
		t.Fatalf("full: %v", err)
	}
	if h.target(a.LocalID) == nil {
		t.Fatal("app removed although its delete was not queued")
	}
}

// refusedRetired leaves one retired 1.x app after a refused adoption.
func refusedRetired(t *testing.T) (*harness, *fakeApp, string) {
	t.Helper()
	api := newFakeAPI()
	m := api.addV1App("Media", "192.168.1.20", 8096, "brave-otter")
	h := newHarness(t, v1App("0123456789abcdef0123456789abcdef", "Media", "192.168.1.20", 8096, m.ID, m.Subdomain))
	h.api = api
	h.start()
	if err := h.e.Remove("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	api.push(passList(), status(403, map[string]string{"error": "account_suspended"}))
	h.settle(20)
	if len(h.e.box.Retired) != 1 || !h.e.box.Adopted {
		t.Fatalf("retired %+v adopted %v", h.e.box.Retired, h.e.box.Adopted)
	}
	return h, m, h.e.box.Retired[0].LocalID
}

func TestRetiredRetriedThenDeleted(t *testing.T) {
	h, _, lid := refusedRetired(t)
	n := len(h.api.requests(pb.DeviceMethod_REGISTER_APPS))
	h.clk.Add(DefaultListEvery / 2)
	h.e.Kick()
	h.settle(20)
	if len(h.api.requests(pb.DeviceMethod_REGISTER_APPS)) != n {
		t.Fatal("refused retired app retried before its refusal expired")
	}
	h.clk.Add(DefaultListEvery)
	h.settle(30)
	registeredOn(t, h.api, 0)
	if len(h.e.box.Retired) != 0 || len(h.e.Status().Refused) != 0 || !h.api.tombstoned(lid) {
		t.Fatalf("retired %+v status %+v", h.e.box.Retired, h.e.Status())
	}
}

func TestRetiredRetriedAfterRestart(t *testing.T) {
	h, _, _ := refusedRetired(t)
	h.restart()
	h.settle(30)
	registeredOn(t, h.api, 0)
	if len(h.e.box.Retired) != 0 {
		t.Fatalf("retired %+v", h.e.box.Retired)
	}
}

func TestRetiredRefusedAgainKeepsServerApp(t *testing.T) {
	h, m, _ := refusedRetired(t)
	h.clk.Add(DefaultListEvery)
	h.api.push(passList(), status(403, map[string]string{"error": "account_suspended"}))
	h.settle(30)
	apps := registeredOn(t, h.api, 1)
	if apps[0].ID != m.ID || apps[0].LocalID != "" || len(h.e.box.Retired) != 1 {
		t.Fatalf("server %+v retired %+v", apps, h.e.box.Retired)
	}
	for _, r := range h.api.requests(pb.DeviceMethod_DELETE_APPS) {
		t.Fatalf("delete sent without a confirmed link: %s", r.Body)
	}
}

func TestRetiredDroppedWhenGoneOrLinkedElsewhere(t *testing.T) {
	for _, linked := range []bool{false, true} {
		h, m, _ := refusedRetired(t)
		other := NewLocalID()
		h.api.mu.Lock()
		if linked {
			m.LocalID = other
		} else {
			h.api.apps = nil
		}
		h.api.mu.Unlock()
		h.clk.Add(DefaultListEvery)
		h.settle(30)
		if len(h.e.box.Retired) != 0 || len(h.e.Status().Refused) != 0 {
			t.Fatalf("linked=%v retired %+v status %+v", linked, h.e.box.Retired, h.e.Status())
		}
		if len(h.api.requests(pb.DeviceMethod_DELETE_APPS)) != 0 {
			t.Fatalf("linked=%v delete sent", linked)
		}
		if linked {
			if apps := registeredOn(t, h.api, 1); apps[0].LocalID != other || !strings.Contains(apps[0].Name, "Media") {
				t.Fatalf("server %+v", apps)
			}
		}
	}
}

func TestRetiredDeleteNeverShared(t *testing.T) {
	h, m, lid := refusedRetired(t)
	wiki, err := h.e.Add("Wiki", "192.168.1.21", 8080)
	if err != nil {
		t.Fatal(err)
	}
	h.settle(20)
	h.clk.Add(DefaultListEvery)
	h.e.Step(context.Background())
	if n := len(h.e.box.Calls); n != 2 {
		t.Fatalf("retry calls %+v", h.e.box.Calls)
	}
	if err := h.e.Remove(wiki); err != nil {
		t.Fatal(err)
	}
	if c := h.e.box.Calls; len(c) != 3 || len(c[2].LocalIDs) != 1 || c[2].LocalIDs[0] != wiki {
		t.Fatalf("calls %+v", c)
	}
	h.api.push(status(403, map[string]string{"error": "account_suspended"}))
	h.settle(30)
	apps := registeredOn(t, h.api, 1)
	if apps[0].ID != m.ID || h.api.tombstoned(lid) {
		t.Fatalf("server %+v tombstones %v", apps, h.api.tombstones)
	}
}

// The name of a removed app now belongs to another server app: adoption
// links that one, which is never deleted.
func TestRetiredAdoptingAnotherAppNeverDeletes(t *testing.T) {
	h, m, lid := refusedRetired(t)
	h.clk.Add(DefaultListEvery)
	var other *fakeApp
	h.api.push(passList(), func(Request) (Response, error, bool, bool) {
		h.api.mu.Lock()
		m.Name = "Media old"
		h.api.mu.Unlock()
		other = h.api.addV1App("Media", "192.168.1.40", 9000, "new-media")
		return Response{}, nil, false, false
	})
	h.settle(30)
	apps := registeredOn(t, h.api, 2)
	for _, r := range h.api.requests(pb.DeviceMethod_DELETE_APPS) {
		t.Fatalf("delete sent: %s", r.Body)
	}
	if len(h.e.box.Retired) != 0 || slices.Contains(h.e.box.Deleted, lid) || slices.Contains(h.e.box.Registered, lid) {
		t.Fatalf("retired %+v deleted %v registered %v", h.e.box.Retired, h.e.box.Deleted, h.e.box.Registered)
	}
	h.clk.Add(DefaultListEvery)
	h.settle(30)
	if got := registeredOn(t, h.api, 2); got[0].ID != apps[0].ID || got[1].ID != other.ID {
		t.Fatalf("server %+v", got)
	}
}

// The removed app is gone from the server and its name is free: the retry
// creates an app, which its delete then removes.
func TestRetiredRetryCreatingAnAppDeletesIt(t *testing.T) {
	h, m, lid := refusedRetired(t)
	h.clk.Add(DefaultListEvery)
	h.api.push(passList(), func(Request) (Response, error, bool, bool) {
		h.api.mu.Lock()
		m.Name = "Media old"
		h.api.mu.Unlock()
		return Response{}, nil, false, false
	})
	h.settle(30)
	apps := registeredOn(t, h.api, 1)
	if apps[0].ID != m.ID || !h.api.tombstoned(lid) || len(h.e.box.Retired) != 0 {
		t.Fatalf("server %+v tombstones %v retired %+v", apps, h.api.tombstones, h.e.box.Retired)
	}
}
