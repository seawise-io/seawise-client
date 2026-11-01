package appsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"

	"github.com/seawise/client/internal/store"
)

func registeredOn(t *testing.T, api *fakeAPI, n int) []fakeApp {
	t.Helper()
	apps := api.live()
	if len(apps) != n {
		t.Fatalf("server has %d apps, want %d: %+v", len(apps), n, apps)
	}
	return apps
}

func TestRegistersLocalApps(t *testing.T) {
	a, b := app("Media", "192.168.1.20", 8096), app("Wiki", "192.168.1.21", 8080)
	h := newHarness(t, a, b)
	h.settle(20)
	apps := registeredOn(t, h.api, 2)
	for _, sa := range apps {
		lt := h.target(sa.LocalID)
		if lt == nil || lt.ServerServiceID != sa.ID || lt.Subdomain != sa.Subdomain {
			t.Fatalf("local %+v does not match server %+v", lt, sa)
		}
	}
	s := h.e.Status()
	if s.OutboxDepth != 0 || s.LastResult != ResultOK || s.LastSync.IsZero() || !s.Adopted {
		t.Fatalf("status %+v", s)
	}
}

func TestNoAppsAdoptsWithoutCalls(t *testing.T) {
	h := newHarness(t)
	h.settle(10)
	if n := len(h.api.requests(pb.DeviceMethod_REGISTER_APPS)); n != 0 {
		t.Fatalf("%d registers for no apps", n)
	}
	if !h.e.Status().Adopted {
		t.Fatal("not adopted")
	}
}

func TestIdleWithoutAccount(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	if err := h.st.Update(func(s *store.State) error { s.Account = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	h.e.Step(context.Background())
	if len(h.api.calls) != 0 || h.e.Status().Mode != ModeOff {
		t.Fatalf("calls %d, status %+v", len(h.api.calls), h.e.Status())
	}
}

// v1 upgrade: apps imported from 1.x have hex ids and a server id; the
// server has them without a local_id. Nothing is duplicated or lost.
func TestV1UpgradeAdoptsWithoutDuplicates(t *testing.T) {
	api := newFakeAPI()
	m := api.addV1App("Media", "192.168.1.20", 8096, "brave-otter")
	w := api.addV1App("Wiki", "192.168.1.21", 8080, "calm-heron")
	// v1 stored stripHtml(name): the local name differs from the server's.
	x := api.addV1App("Notes b", "192.168.1.22", 3000, "quiet-tern")
	local := []store.Target{
		v1App("0123456789abcdef0123456789abcdef", "Media", "192.168.1.20", 8096, m.ID, m.Subdomain),
		v1App("fedcba9876543210fedcba9876543210", "Wiki", "192.168.1.21", 8080, w.ID, w.Subdomain),
		v1App("00112233445566778899aabbccddeeff", "Notes <b>b</b>", "192.168.1.22", 3000, x.ID, x.Subdomain),
	}
	h := newHarness(t, local...)
	h.api = api
	h.start()
	h.settle(20)

	apps := registeredOn(t, api, 3)
	byID := map[string]fakeApp{}
	for _, a := range apps {
		byID[a.ID] = a
	}
	for _, want := range []*fakeApp{m, w, x} {
		got, ok := byID[want.ID]
		if !ok || got.Subdomain != want.Subdomain || got.LocalID == "" {
			t.Fatalf("app %s lost or changed: %+v", want.Name, got)
		}
		lt := h.target(got.LocalID)
		if lt == nil || lt.ServerServiceID != want.ID || lt.Subdomain != want.Subdomain || !ValidLocalID(lt.LocalID) {
			t.Fatalf("local target for %s: %+v", want.Name, lt)
		}
	}
	if len(h.targets()) != 3 {
		t.Fatalf("local targets %d", len(h.targets()))
	}
	if lt := h.target(byID[x.ID].LocalID); lt.Name != "Notes b" {
		t.Fatalf("adopted name %q", lt.Name)
	}
	for _, r := range api.requests(pb.DeviceMethod_REGISTER_APPS) {
		if bytes.Contains(r.Body, []byte("<b>")) {
			t.Fatal("registered the v1 local name instead of the listed one")
		}
	}
	// A restart and another sync change nothing.
	h.restart()
	h.clk.Add(time.Hour)
	h.settle(20)
	registeredOn(t, api, 3)
}

// Amendment 1: every local app is registered and acknowledged before any
// queued delete goes out.
func TestAdoptionBeforeQueuedDeletes(t *testing.T) {
	api := newFakeAPI()
	m := api.addV1App("Media", "192.168.1.20", 8096, "brave-otter")
	o := api.addV1App("Old", "192.168.1.30", 81, "old-one")
	h := newHarness(t,
		v1App("0123456789abcdef0123456789abcdef", "Media", "192.168.1.20", 8096, m.ID, m.Subdomain),
		v1App("fedcba9876543210fedcba9876543210", "Old", "192.168.1.30", 81, o.ID, o.Subdomain))
	h.api = api
	h.start()
	// The first register fails: no delete may overtake it.
	api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }), fail503())
	h.e.Step(context.Background()) // list + adoption queued
	var oldID string
	for _, tg := range h.targets() {
		if tg.Name == "Old" {
			oldID = tg.LocalID
		}
	}
	if err := h.e.Remove(oldID); err != nil {
		t.Fatal(err)
	}
	h.settle(30)
	var order []pb.DeviceMethod
	for _, r := range api.calls {
		if r.Method != pb.DeviceMethod_LIST_APPS {
			order = append(order, r.Method)
		}
	}
	firstDelete, lastRegisterBefore := -1, -1
	for i, m := range order {
		if m == pb.DeviceMethod_DELETE_APPS && firstDelete < 0 {
			firstDelete = i
		}
		if m == pb.DeviceMethod_REGISTER_APPS && firstDelete < 0 {
			lastRegisterBefore = i
		}
	}
	if firstDelete < 0 || lastRegisterBefore < 0 || firstDelete < lastRegisterBefore {
		t.Fatalf("order %v", order)
	}
	apps := registeredOn(t, api, 1)
	if apps[0].ID != m.ID {
		t.Fatalf("wrong app left: %+v", apps)
	}
	if !api.tombstoned(oldID) {
		t.Fatal("deleted app has no tombstone")
	}
}

func TestOfflineChangesSurvive(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.settle(20)
	for i := 0; i < 5; i++ {
		h.api.push(timeout())
	}
	id, err := h.e.Add("B", "10.0.0.2", 81)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		h.clk.Add(h.e.Step(context.Background()))
	}
	h.restart()
	h.settle(30)
	if h.api.byLocal(id) == nil {
		t.Fatal("app added offline never registered")
	}
	registeredOn(t, h.api, 2)
}

func TestRetrySameKeyAndBody(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }))
	h.api.push(fail503(), fail429(2*time.Second), timeout(), nonceChallenge(), proofCode("replayed"), status(502, map[string]string{}))
	h.settle(40)
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) != 7 {
		t.Fatalf("%d register attempts, want 7", len(regs))
	}
	for _, r := range regs[1:] {
		if r.Key != regs[0].Key || !bytes.Equal(r.Body, regs[0].Body) {
			t.Fatal("retry changed key or body")
		}
	}
	registeredOn(t, h.api, 1)
}

func TestBackoffCappedAndRetryAfter(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }))
	for i := 0; i < 12; i++ {
		h.api.push(fail503())
	}
	h.e.Step(context.Background())
	var last time.Duration
	for i := 0; i < 12; i++ {
		last = h.e.Step(context.Background())
		h.clk.Add(last)
		if last > MaxBackoff {
			t.Fatalf("backoff %v over the cap", last)
		}
	}
	if last != MaxBackoff {
		t.Fatalf("backoff %v, want the cap", last)
	}
	h.api.push(fail429(20 * time.Second))
	d := h.e.Step(context.Background())
	if d != 20*time.Second && d != MaxBackoff {
		t.Fatalf("Retry-After not honoured: %v", d)
	}
	h.clk.Add(d)
	h.api.push(fail429(time.Hour))
	if d := h.e.Step(context.Background()); d != MaxBackoff {
		t.Fatalf("Retry-After over the cap: %v", d)
	}
	if s := h.e.Status(); s.LastResult != ResultRetrying || s.HeadAttempts < 12 {
		t.Fatalf("status %+v", s)
	}
}

func TestNonceChallengeRetriesAtOnce(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }))
	h.e.Step(context.Background())
	h.api.push(nonceChallenge())
	if d := h.e.Step(context.Background()); d != 0 {
		t.Fatalf("first nonce challenge waited %v", d)
	}
	h.api.push(nonceChallenge(), nonceChallenge())
	h.e.Step(context.Background())
	if d := h.e.Step(context.Background()); d == 0 {
		t.Fatal("repeated nonce challenges never back off")
	}
}

// A crash between sending a call and recording its answer is safe: the
// retry carries the same key, and the server returns the stored answer.
func TestCrashAfterSendReplaysStoredAnswer(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }), lostAnswer())
	h.e.Step(context.Background())
	h.e.Step(context.Background())
	h.restart()
	h.settle(20)
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) != 2 || regs[0].Key != regs[1].Key || !bytes.Equal(regs[0].Body, regs[1].Body) {
		t.Fatalf("register attempts %d", len(regs))
	}
	registeredOn(t, h.api, 2)
	for _, tg := range h.targets() {
		if tg.ServerServiceID == "" || tg.Subdomain == "" {
			t.Fatalf("answer not applied after restart: %+v", tg)
		}
	}
}

func TestCrashAfterDeleteSendIsSafe(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	h.api.push(lostAnswer())
	if err := h.e.Remove(a.LocalID); err != nil {
		t.Fatal(err)
	}
	h.e.Step(context.Background())
	h.restart()
	h.settle(20)
	registeredOn(t, h.api, 0)
	if len(h.targets()) != 0 {
		t.Fatal("deleted app came back")
	}
	dels := h.api.requests(pb.DeviceMethod_DELETE_APPS)
	if len(dels) != 2 || dels[0].Key != dels[1].Key {
		t.Fatalf("delete attempts %d", len(dels))
	}
}

// A crash after the delete intent is written but before the target is
// removed still removes the target and sends the delete.
func TestRemoveInterruptedFinishesOnRestart(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	h.e.failRemoveTarget = true
	if err := h.e.Remove(a.LocalID); err == nil {
		t.Fatal("expected the injected failure")
	}
	h.restart()
	h.settle(20)
	if len(h.targets()) != 0 {
		t.Fatal("target kept")
	}
	registeredOn(t, h.api, 0)
}

func TestNeverDeletesOnAbsence(t *testing.T) {
	a, b := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81)
	h := newHarness(t, a, b)
	h.settle(20)
	// The server loses an app without a tombstone and lists nothing.
	h.api.mu.Lock()
	h.api.apps = nil
	h.api.mu.Unlock()
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if len(h.targets()) != 2 {
		t.Fatal("a local app was removed because the list lacked it")
	}
	registeredOn(t, h.api, 2)
	if len(h.api.requests(pb.DeviceMethod_DELETE_APPS)) != 0 {
		t.Fatal("delete sent from absence")
	}
}

func TestEmptyListReRegisters(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, status(200, map[string]any{"apps": []any{}, "deleted": []any{}})))
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if len(h.targets()) != 1 || len(h.api.requests(pb.DeviceMethod_REGISTER_APPS)) != 2 {
		t.Fatal("empty list not answered by a register")
	}
}

func TestMalformedListChangesNothing(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	for _, body := range []string{`{"apps":null,"deleted":[]}`, `{"apps":[]}`, `{}`, `[]`, `{"apps":[],"deleted":[]} x`} {
		h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) {
			return Response{Status: 200, Body: []byte(body)}, nil, true, false
		}))
		h.clk.Add(DefaultListEvery)
		h.e.Step(context.Background())
		if len(h.targets()) != 1 || h.e.Status().LastError == "" {
			t.Fatalf("%s: targets %d status %+v", body, len(h.targets()), h.e.Status())
		}
	}
}

func TestTombstoneFromOwnerDelete(t *testing.T) {
	a, b := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81)
	h := newHarness(t, a, b)
	h.settle(20)
	h.api.ownerDelete(a.LocalID)
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if h.target(a.LocalID) != nil || h.target(b.LocalID) == nil {
		t.Fatal("owner delete not applied locally")
	}
	registeredOn(t, h.api, 1)
	// Never registered again.
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	for _, r := range h.api.requests(pb.DeviceMethod_REGISTER_APPS)[1:] {
		if bytes.Contains(r.Body, []byte(a.LocalID)) {
			t.Fatal("tombstoned local_id sent again")
		}
	}
}

func TestTombstoneInRegisterAnswer(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.mu.Lock()
	h.api.tombstones = []string{a.LocalID}
	h.api.mu.Unlock()
	// A list that hides the tombstone, so the register meets it.
	h.api.push(only(pb.DeviceMethod_LIST_APPS, status(200, map[string]any{"apps": []any{}, "deleted": []any{}})))
	h.settle(20)
	if len(h.targets()) != 0 {
		t.Fatal("deleted result did not remove the app")
	}
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if n := len(h.api.requests(pb.DeviceMethod_REGISTER_APPS)); n != 1 {
		t.Fatalf("%d registers; a deleted local_id was sent again", n)
	}
	registeredOn(t, h.api, 0)
}

// Amendment 5: only local_ids the server confirmed are deleted.
func TestDeleteOnlyRegistered(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t)
	h.settle(10)
	if err := h.st.Update(func(s *store.State) error { s.Targets = append(s.Targets, a); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.e.Remove(a.LocalID); err != nil {
		t.Fatal(err)
	}
	h.settle(20)
	if n := len(h.api.requests(pb.DeviceMethod_DELETE_APPS)); n != 0 {
		t.Fatalf("%d deletes for a never registered app", n)
	}
	if len(h.targets()) != 0 {
		t.Fatal("target kept")
	}
}

func TestRemoveWhileRegisterQueuedDeletesAfter(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }), timeout())
	h.e.Step(context.Background())
	h.e.Step(context.Background()) // register outcome unknown
	if err := h.e.Remove(a.LocalID); err != nil {
		t.Fatal(err)
	}
	h.settle(20)
	registeredOn(t, h.api, 0)
	if !h.api.tombstoned(a.LocalID) {
		t.Fatal("no tombstone")
	}
}

func TestIdempotencyMismatchLoggedAndDropped(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
		status(409, map[string]string{"error": "idempotency_mismatch"}))
	var logs bytes.Buffer
	h.e.log = testLogger(&logs)
	h.settle(20)
	if !strings.Contains(logs.String(), "idempotency_mismatch") || !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("mismatch not logged as an error: %s", logs.String())
	}
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) != 2 || regs[0].Key == regs[1].Key {
		t.Fatal("mismatch was retried under the same key")
	}
	registeredOn(t, h.api, 1)
}

// Amendment 2: name_taken recovers a lost local state by taking the listed
// local_id of the same-name app, and the rest of the batch is not lost.
func TestNameTakenRecoversListedLocalID(t *testing.T) {
	api := newFakeAPI()
	h0 := newHarness(t, app("Media", "10.0.0.1", 80))
	h0.api = api
	h0.start()
	h0.settle(20)
	oldID := api.live()[0].LocalID

	// State lost: the same app comes back under a new local_id, with another.
	h := newHarness(t, app("Media", "10.0.0.1", 80), app("Wiki", "10.0.0.2", 81))
	h.api = api
	h.start()
	h.settle(30)
	apps := registeredOn(t, api, 2)
	if h.target(oldID) == nil {
		t.Fatalf("local app did not take the listed local_id %s: %+v", oldID, h.targets())
	}
	for _, a := range apps {
		if h.target(a.LocalID) == nil {
			t.Fatalf("server app %+v not linked locally", a)
		}
	}
}

func TestNameTakenWithoutListedIDIsRefused(t *testing.T) {
	a := app("Media", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
		status(409, map[string]any{"error": "name_taken", "index": 0, "local_id": a.LocalID}))
	h.settle(20)
	s := h.e.Status()
	if len(s.Refused) != 1 || s.Refused[0].LocalID != a.LocalID || h.target(a.LocalID) == nil {
		t.Fatalf("status %+v", s)
	}
}

// Amendment 3: unlinked apps are shown, never deleted.
func TestUnlinkedAppsShownNotTouched(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.settle(20)
	u := h.api.addV1App("Other", "10.0.0.9", 99, "other")
	h.api.mu.Lock()
	h.api.seq++
	h.api.apps = append(h.api.apps, &fakeApp{ID: "cccccccc-0000-4000-8000-000000000001", LocalID: "dddddddd-0000-4000-8000-000000000001", Name: "Foreign", Host: "1.1.1.1", Port: 1, Subdomain: "foreign", Created: 99})
	h.api.mu.Unlock()
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	s := h.e.Status()
	if len(s.Unlinked) != 1 || s.Unlinked[0].ID != u.ID || s.Unlinked[0].Name != "Other" || s.UnknownOnServer != 1 {
		t.Fatalf("status %+v", s)
	}
	registeredOn(t, h.api, 3)
	if len(h.targets()) != 1 || len(h.api.requests(pb.DeviceMethod_DELETE_APPS)) != 0 {
		t.Fatal("unlinked or unknown app changed something")
	}
}

// Amendment 4: invalid_proof and key_revoked go to identity recovery; the
// call stays queued and is never answered by them.
func TestIdentityErrorsKeepTheCall(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
		proofCode("key_revoked"), proofCode("invalid_proof"))
	h.settle(20)
	if len(h.ident) != 2 || h.ident[0] != "key_revoked" || h.ident[1] != "invalid_proof" {
		t.Fatalf("identity callbacks %v", h.ident)
	}
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) != 3 || regs[0].Key != regs[2].Key {
		t.Fatal("identity error ended the call")
	}
	registeredOn(t, h.api, 1)
}

func TestRefusedBatchIsSplit(t *testing.T) {
	a, b, c := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81), app("C", "10.0.0.3", 82)
	h := newHarness(t, a, b, c)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
		status(403, map[string]string{"error": "limit_reached"}))
	h.settle(20)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }))
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	registeredOn(t, h.api, 3)
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) != 4 {
		t.Fatalf("%d registers, want the batch then one per app", len(regs))
	}
}

func TestSingleRefusalShownAndLocalKept(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
		status(403, map[string]string{"error": "account_suspended"}))
	h.settle(20)
	s := h.e.Status()
	if s.LastResult != ResultRefused || len(s.Refused) != 1 || s.Refused[0].Reason != "account_suspended" || h.target(a.LocalID) == nil {
		t.Fatalf("status %+v", s)
	}
}

func TestInvalidLocalAppNotSent(t *testing.T) {
	bad := app("bad\x01name", "10.0.0.1", 80)
	good := app("Good", "10.0.0.2", 81)
	h := newHarness(t, bad, good)
	h.settle(20)
	registeredOn(t, h.api, 1)
	s := h.e.Status()
	if len(s.Refused) != 1 || s.Refused[0].LocalID != bad.LocalID {
		t.Fatalf("status %+v", s)
	}
}

func TestDisabledAppsNotRegistered(t *testing.T) {
	d := app("Off", "10.0.0.1", 80)
	d.Disabled = true
	h := newHarness(t, d)
	h.settle(20)
	registeredOn(t, h.api, 0)
}

func TestLocalEditReRegisters(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	if err := h.st.Update(func(s *store.State) error { s.Targets[0].Port = 9090; return nil }); err != nil {
		t.Fatal(err)
	}
	h.e.Kick()
	h.settle(20)
	if got := h.api.byLocal(a.LocalID); got == nil || got.Port != 9090 {
		t.Fatalf("edit not sent: %+v", got)
	}
}

func TestBatchesOfFifty(t *testing.T) {
	var ts []store.Target
	for i := 0; i < 120; i++ {
		ts = append(ts, app("app-"+itoa(i), "10.0.0.1", 1000+i))
	}
	h := newHarness(t, ts...)
	h.settle(40)
	registeredOn(t, h.api, 120)
	for _, r := range h.api.requests(pb.DeviceMethod_REGISTER_APPS) {
		var b struct {
			Apps []RegisterItem `json:"apps"`
		}
		if err := json.Unmarshal(r.Body, &b); err != nil || len(b.Apps) > MaxItems || len(r.Body) > MaxBody {
			t.Fatalf("batch of %d, %d bytes", len(b.Apps), len(r.Body))
		}
	}
}

func TestRegisterBodyShape(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	a.IconURL = "https://example.test/i.png"
	h := newHarness(t, a)
	h.settle(20)
	r := h.api.requests(pb.DeviceMethod_REGISTER_APPS)[0]
	want := `{"apps":[{"local_id":"` + a.LocalID + `","name":"A","host":"10.0.0.1","port":80,"icon_url":"https://example.test/i.png","public_local":true}]}`
	if string(r.Body) != want || !keyRe.MatchString(r.Key) {
		t.Fatalf("body %s key %q", r.Body, r.Key)
	}
}

func TestHealthLatestWins(t *testing.T) {
	a, b := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81)
	h := newHarness(t, a, b)
	h.settle(20)
	h.api.push(only(pb.DeviceMethod_REPORT_HEALTH, fail503()))
	h.e.SetHealth(map[string]string{a.LocalID: "online", b.LocalID: "online"})
	h.e.Step(context.Background())
	h.e.SetHealth(map[string]string{a.LocalID: "offline", b.LocalID: "online"})
	h.settle(20)
	if len(h.api.health) != 1 {
		t.Fatalf("health reports %d", len(h.api.health))
	}
	if !bytes.Contains(h.api.health[0], []byte(`"local_id":"`+a.LocalID+`","status":"offline"`)) {
		t.Fatalf("stale health sent: %s", h.api.health[0])
	}
	for _, r := range h.api.requests(pb.DeviceMethod_REPORT_HEALTH) {
		if r.Key != "" {
			t.Fatal("health carries a queued call key")
		}
	}
}

func TestOutboxFileModeAndServerSwitch(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }), timeout())
	h.e.Step(context.Background())
	h.e.Step(context.Background())
	fi, err := os.Stat(filepath.Join(h.st.Dir(), OutboxFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("outbox file: %v %v", fi, err)
	}
	if h.e.Status().OutboxDepth != 1 {
		t.Fatalf("depth %d", h.e.Status().OutboxDepth)
	}
	// Paired to another server: the old outbox is not sent there.
	if err := h.st.Update(func(s *store.State) error {
		s.Account.ServerID = "99999999-2222-4333-8444-555555555555"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := len(h.api.requests(pb.DeviceMethod_REGISTER_APPS))
	h.e.Step(context.Background())
	regs := h.api.requests(pb.DeviceMethod_REGISTER_APPS)
	if len(regs) > before && regs[len(regs)-1].Key == regs[0].Key {
		t.Fatal("old server's call sent after re-pairing")
	}
}

func TestCorruptOutboxRefused(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	p := filepath.Join(h.st.Dir(), OutboxFile)
	if err := os.WriteFile(p, []byte(`{"schema":1,"bogus":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Store: h.st, Carrier: h.api}); err == nil {
		t.Fatal("corrupt outbox accepted")
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Store: h.st, Carrier: h.api}); err == nil {
		t.Fatal("group-readable outbox accepted")
	}
}

func TestAddValidates(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct {
		name, host string
		port       int
	}{{"", "h", 1}, {"a", "", 1}, {"a", "h", 0}, {"a", "h", 70000}, {"a\nb", "h", 1}, {"a", "h h", 1}} {
		if _, err := h.e.Add(c.name, c.host, c.port); err == nil {
			t.Fatalf("Add(%q,%q,%d) accepted", c.name, c.host, c.port)
		}
	}
	id, err := h.e.Add("ok", "host.local", 8080)
	if err != nil || !ValidLocalID(id) {
		t.Fatalf("Add: %q %v", id, err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.e.Run(ctx, func() bool { return true }) }()
	h.e.Kick()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestListNonceChallengeRetriedAtOnce(t *testing.T) {
	h := newHarness(t)
	h.api.push(nonceChallenge())
	h.e.Step(context.Background())
	if len(h.api.requests(pb.DeviceMethod_LIST_APPS)) != 2 || !h.e.Status().Adopted {
		t.Fatalf("status %+v", h.e.Status())
	}
}

func TestBackoffSequence(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }))
	h.e.Step(context.Background())
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i, w := range want {
		h.api.push(fail503())
		d := h.e.Step(context.Background())
		if d != w*time.Second {
			t.Fatalf("failure %d: backoff %v, want %v", i+1, d, w*time.Second)
		}
		h.clk.Add(d)
	}
	h.api.push(fail429(MaxBackoff))
	if d := h.e.Step(context.Background()); d != MaxBackoff {
		t.Fatal(d)
	}
}

func TestRetryAfterAboveBackoff(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }), fail429(5*time.Second))
	h.e.Step(context.Background())
	if d := h.e.Step(context.Background()); d != 5*time.Second {
		t.Fatalf("Retry-After ignored: %v", d)
	}
}

func TestQueuedDeletesShareOneCall(t *testing.T) {
	a, b, c := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81), app("C", "10.0.0.3", 82)
	h := newHarness(t, a, b, c)
	h.settle(20)
	h.api.push(timeout())
	for _, x := range []store.Target{a, b, c} {
		if err := h.e.Remove(x.LocalID); err != nil {
			t.Fatal(err)
		}
	}
	if d := h.e.Status().OutboxDepth; d != 2 {
		t.Fatalf("outbox depth %d, want the head and one grown call", d)
	}
	h.settle(20)
	dels := h.api.requests(pb.DeviceMethod_DELETE_APPS)
	if len(dels) != 3 || !bytes.Contains(dels[2].Body, []byte(b.LocalID)) || !bytes.Contains(dels[2].Body, []byte(c.LocalID)) {
		t.Fatalf("%d deletes", len(dels))
	}
	registeredOn(t, h.api, 0)
}

func TestDeleteCallGrowsToFiftyIDs(t *testing.T) {
	var ts []store.Target
	for i := 0; i < 52; i++ {
		ts = append(ts, app("app-"+itoa(i), "10.0.0.1", 1000+i))
	}
	h := newHarness(t, ts...)
	h.settle(30)
	h.api.push(timeout())
	for _, x := range ts {
		if err := h.e.Remove(x.LocalID); err != nil {
			t.Fatal(err)
		}
	}
	if d := h.e.Status().OutboxDepth; d != 3 {
		t.Fatalf("outbox depth %d, want 1 + 50 + 1 ids", d)
	}
	h.settle(30)
	registeredOn(t, h.api, 0)
}

func TestHealthChunksAndFilters(t *testing.T) {
	var ts []store.Target
	st := map[string]string{}
	for i := 0; i < 51; i++ {
		a := app("app-"+itoa(i), "10.0.0.1", 1000+i)
		ts = append(ts, a)
		st[a.LocalID] = "online"
	}
	h := newHarness(t, ts...)
	h.settle(20)
	st[ts[0].LocalID] = "starting"
	st[NewLocalID()] = "online"
	h.e.SetHealth(st)
	h.settle(20)
	if len(h.api.health) != 1 {
		t.Fatalf("health requests %d", len(h.api.health))
	}
	if bytes.Contains(h.api.health[0], []byte(ts[0].LocalID)) {
		t.Fatal("unknown status sent")
	}
	h.e.SetHealth(map[string]string{ts[0].LocalID: "online", ts[1].LocalID: "offline"})
	h.e.SetHealth(st)
	st[ts[0].LocalID] = "online"
	h.e.SetHealth(st)
	h.settle(20)
	if len(h.api.health) != 3 {
		t.Fatalf("health requests %d, want one of 50 then one of 1", len(h.api.health))
	}
}

func TestNameTakenByIndex(t *testing.T) {
	a := app("Media", "10.0.0.1", 80)
	h := newHarness(t, a)
	idx := 0
	h.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
		status(409, map[string]any{"error": "name_taken", "index": idx}))
	h.settle(20)
	if s := h.e.Status(); len(s.Refused) != 1 || s.Refused[0].Reason != "name_taken" {
		t.Fatalf("status %+v", s)
	}
	for _, bad := range []int{-1, 1} {
		h2 := newHarness(t, app("Media", "10.0.0.1", 80))
		h2.api.push(only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false }),
			status(409, map[string]any{"error": "name_taken", "index": bad}))
		h2.settle(20)
		if s := h2.e.Status(); len(s.Refused) != 1 || len(h2.api.requests(pb.DeviceMethod_REGISTER_APPS)) != 1 {
			t.Fatalf("index %d: %+v", bad, s)
		}
	}
}

func TestSubdomainDiffersIsANotice(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	a.Subdomain = "mine"
	h := newHarness(t, a)
	h.settle(20)
	if got := h.target(a.LocalID).Subdomain; got != "mine" {
		t.Fatalf("subdomain replaced: %q", got)
	}
	if s := h.e.Status(); len(s.Notices) != 1 || !strings.Contains(s.Notices[0], a.LocalID) {
		t.Fatalf("status %+v", s)
	}
}

func TestListRecordsServerFields(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	if err := h.st.Update(func(s *store.State) error { s.Targets[0].ServerServiceID, s.Targets[0].Subdomain = "", ""; return nil }); err != nil {
		t.Fatal(err)
	}
	changes := 0
	h.e.cfg.OnChange = func(context.Context) { changes++ }
	h.e.Kick()
	h.settle(20)
	tg := h.target(a.LocalID)
	if tg.ServerServiceID == "" || tg.Subdomain == "" || changes == 0 {
		t.Fatalf("%+v changes %d", tg, changes)
	}
	changes = 0
	h.e.Kick()
	h.settle(20)
	if changes != 0 {
		t.Fatal("unchanged list reported a change")
	}
}

func TestRunInactiveIsOff(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = h.e.Run(ctx, func() bool { return false }); close(done) }()
	h.e.Kick()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if len(h.api.calls) != 0 || h.e.Status().Mode != ModeOff {
		t.Fatal("inactive engine made calls")
	}
}

func passList() fault {
	return only(pb.DeviceMethod_LIST_APPS, func(Request) (Response, error, bool, bool) { return Response{}, nil, false, false })
}

// H: an app deleted on the website before the first v2 sync stays gone.
func TestAdoptionKeepsOwnerDeletedAppGone(t *testing.T) {
	api := newFakeAPI()
	m := api.addV1App("Media", "192.168.1.20", 8096, "brave-otter")
	gone := v1App("fedcba9876543210fedcba9876543210", "Old", "192.168.1.30", 81, "aaaaaaaa-0000-4000-8000-000000000099", "old-one")
	h := newHarness(t, v1App("0123456789abcdef0123456789abcdef", "Media", "192.168.1.20", 8096, m.ID, m.Subdomain), gone)
	h.api = api
	h.start()
	h.settle(20)
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	registeredOn(t, api, 1)
	for _, r := range api.requests(pb.DeviceMethod_REGISTER_APPS) {
		if bytes.Contains(r.Body, []byte(`"Old"`)) {
			t.Fatal("owner-deleted app registered again")
		}
	}
	for _, tg := range h.targets() {
		if tg.Name == "Old" && (!tg.Disabled || tg.ServerServiceID != "" || tg.Subdomain != "") {
			t.Fatalf("owner-deleted app not disabled as in v1: %+v", tg)
		}
	}
}

func TestServerDisableRequestNotRegistered(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	now := time.Now()
	a.ServerDisableRequestedAt = &now
	h := newHarness(t, a)
	h.settle(20)
	registeredOn(t, h.api, 0)
}

// M1: a v1 app deleted locally before the first v2 sync is adopted and
// then deleted on the server.
func TestRemoveBeforeAdoptionDeletesV1App(t *testing.T) {
	for _, listFirst := range []bool{false, true} {
		api := newFakeAPI()
		m := api.addV1App("Media", "192.168.1.20", 8096, "brave-otter")
		k := api.addV1App("Keep", "192.168.1.21", 8097, "keep-it")
		h := newHarness(t,
			v1App("0123456789abcdef0123456789abcdef", "Media", "192.168.1.20", 8096, m.ID, m.Subdomain),
			v1App("fedcba9876543210fedcba9876543210", "Keep", "192.168.1.21", 8097, k.ID, k.Subdomain))
		h.api = api
		h.start()
		id := "0123456789abcdef0123456789abcdef"
		if listFirst {
			api.push(timeout())
			h.e.Step(context.Background())
			id = ""
			for _, tg := range h.targets() {
				if tg.Name == "Media" {
					id = tg.LocalID
				}
			}
			h.clk.Add(time.Minute)
		}
		if err := h.e.Remove(id); err != nil {
			t.Fatal(err)
		}
		h.settle(30)
		apps := registeredOn(t, api, 1)
		if len(h.e.box.Retired) != 0 {
			t.Fatalf("retired kept after adoption: %+v", h.e.box.Retired)
		}
		if apps[0].ID != k.ID || len(h.targets()) != 1 {
			t.Fatalf("listFirst=%v: server %+v local %+v", listFirst, apps, h.targets())
		}
	}
}

// M2: deleted answers that are not authenticated never remove local apps.
func TestRelayedDeletedOnlyReported(t *testing.T) {
	a, b := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81)
	h := newHarness(t, a, b)
	h.settle(20)
	h.api.relayed = true
	h.api.ownerDelete(a.LocalID)
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if h.target(a.LocalID) == nil {
		t.Fatal("relayed list removed an app")
	}
	if s := h.e.Status(); !strings.Contains(strings.Join(s.Notices, " "), "server_reports_deleted:"+a.LocalID) {
		t.Fatalf("not reported: %+v", s)
	}
	if h.target(a.LocalID) == nil || h.target(b.LocalID) == nil {
		t.Fatal("relayed register answer removed an app")
	}
	h.api.relayed = false
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if h.target(a.LocalID) != nil {
		t.Fatal("authenticated list did not apply the owner delete")
	}
}

// L1: a failed outbox write leaves the outbox and the app as they were.
func TestRemoveSaveFailureRestores(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	h.e.saveHook = func() error { return errors.New("disk full") }
	if err := h.e.Remove(a.LocalID); err == nil {
		t.Fatal("expected the write failure")
	}
	h.e.saveHook = nil
	if h.target(a.LocalID) == nil || h.e.Status().OutboxDepth != 0 {
		t.Fatalf("state changed: %+v", h.e.Status())
	}
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if h.target(a.LocalID) == nil || len(h.api.requests(pb.DeviceMethod_DELETE_APPS)) != 0 {
		t.Fatal("failed remove took effect later")
	}
}

// L2: no relink when the app was renamed after the call.
func TestNoRelinkAfterRename(t *testing.T) {
	api := newFakeAPI()
	h0 := newHarness(t, app("Media", "10.0.0.1", 80))
	h0.api = api
	h0.start()
	h0.settle(20)
	a := app("Media", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api = api
	h.start()
	h.e.Step(context.Background()) // adoption list
	h.e.Step(context.Background()) // name_taken
	if err := h.st.Update(func(s *store.State) error { s.Targets[0].Name = "Renamed"; return nil }); err != nil {
		t.Fatal(err)
	}
	h.settle(20)
	if h.target(a.LocalID) == nil {
		t.Fatal("renamed app relinked to another app's local_id")
	}
}

// L3: a name_taken answer naming no app of the call refuses the call's
// apps for a while instead of looping.
func TestNameTakenUnmatchedNoLoop(t *testing.T) {
	a := app("Media", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.push(passList(), status(409, map[string]any{"error": "name_taken", "local_id": "dddddddd-0000-4000-8000-000000000001"}))
	h.settle(20)
	if n := len(h.api.requests(pb.DeviceMethod_REGISTER_APPS)); n != 1 {
		t.Fatalf("%d registers", n)
	}
	if s := h.e.Status(); len(s.Refused) != 1 {
		t.Fatalf("status %+v", s)
	}
}

// L4: the identity callback's error is shown.
func TestIdentityRecoveryErrorShown(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.identErr = errors.New("pair this device again")
	h.api.push(passList(), proofCode("key_revoked"))
	h.e.Step(context.Background())
	h.e.Step(context.Background())
	if s := h.e.Status(); !strings.Contains(s.LastError, "pair this device again") || s.LastResult != ResultIdentity {
		t.Fatalf("status %+v", s)
	}
}

// L5: Listed reports a successful v2 list for the paired server.
func TestListedAfterFirstList(t *testing.T) {
	h := newHarness(t)
	if h.e.Listed() {
		t.Fatal("listed before any list")
	}
	h.api.push(timeout())
	h.e.Step(context.Background())
	if h.e.Listed() {
		t.Fatal("listed after a failed list")
	}
	h.clk.Add(time.Minute)
	h.settle(10)
	if !h.e.Listed() {
		t.Fatal("not listed after a list")
	}
}

// L6: the listed name is sent in the body and saved only after a 2xx.
func TestAdoptionRenameAfterSuccess(t *testing.T) {
	api := newFakeAPI()
	x := api.addV1App("Notes b", "192.168.1.22", 3000, "quiet-tern")
	h := newHarness(t, v1App("00112233445566778899aabbccddeeff", "Notes <b>b</b>", "192.168.1.22", 3000, x.ID, x.Subdomain))
	h.api = api
	h.start()
	api.push(passList(), fail503())
	h.e.Step(context.Background())
	h.e.Step(context.Background())
	if n := h.targets()[0].Name; n != "Notes <b>b</b>" {
		t.Fatalf("renamed before a 2xx: %q", n)
	}
	if r := api.requests(pb.DeviceMethod_REGISTER_APPS)[0]; !bytes.Contains(r.Body, []byte(`"name":"Notes b"`)) {
		t.Fatalf("body %s", r.Body)
	}
	h.settle(20)
	if n := h.targets()[0].Name; n != "Notes b" {
		t.Fatalf("name %q after adoption", n)
	}
	registeredOn(t, api, 1)
}

func TestRelayedRegisterDeletedOnlyReported(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.relayed = true
	h.api.mu.Lock()
	h.api.tombstones = []string{a.LocalID}
	h.api.mu.Unlock()
	h.api.push(only(pb.DeviceMethod_LIST_APPS, status(200, map[string]any{"apps": []any{}, "deleted": []any{}})))
	h.settle(20)
	h.e.Step(context.Background())
	if h.target(a.LocalID) == nil {
		t.Fatal("relayed register answer removed the app")
	}
	if !strings.Contains(strings.Join(h.e.Status().Notices, " "), "server_reports_deleted:"+a.LocalID) {
		t.Fatalf("not reported: %+v", h.e.Status())
	}
}

const otherServer = "99999999-2222-4333-8444-555555555555"

func repair(t *testing.T, h *harness) *fakeAPI {
	t.Helper()
	if err := h.st.Update(func(s *store.State) error { s.Account.ServerID = otherServer; return nil }); err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI()
	h.api = api
	h.start()
	return api
}

// M2: re-pairing registers every app on the new server and disables none.
func TestRepairRegistersAllDisablesNone(t *testing.T) {
	for _, before := range []bool{true, false} {
		api := newFakeAPI()
		m := api.addV1App("Media", "192.168.1.20", 8096, "brave-otter")
		w := api.addV1App("Wiki", "192.168.1.21", 8080, "calm-heron")
		h := newHarness(t,
			v1App("0123456789abcdef0123456789abcdef", "Media", "192.168.1.20", 8096, m.ID, m.Subdomain),
			v1App("fedcba9876543210fedcba9876543210", "Wiki", "192.168.1.21", 8080, w.ID, w.Subdomain))
		h.api = api
		h.start()
		if before {
			h.settle(20)
		}
		other := repair(t, h)
		h.settle(20)
		registeredOn(t, other, 2)
		for _, tg := range h.targets() {
			if tg.Disabled || tg.ServerServiceID == m.ID || tg.ServerServiceID == w.ID || tg.ServerServiceID == "" {
				t.Fatalf("before=%v: %+v", before, tg)
			}
		}
	}
}

// L1: binding the outbox from no server keeps what was queued.
func TestBindFromNoServerKeepsOutbox(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	acc := h.st.State().Account
	if err := h.st.Update(func(s *store.State) error { s.Account = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := h.e.Remove(a.LocalID); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Update(func(s *store.State) error { s.Account = acc; return nil }); err != nil {
		t.Fatal(err)
	}
	h.settle(20)
	if !slices.Contains(h.e.box.Deleted, a.LocalID) {
		t.Fatal("deleted set dropped when the outbox was bound")
	}
}

// L2: a refused adoption keeps a removed 1.x app visible as refused.
func TestRefusedAdoptionKeepsRetired(t *testing.T) {
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
	check := func() {
		s := h.e.Status()
		if len(s.Refused) != 1 || len(h.e.box.Retired) != 1 || s.Refused[0].LocalID != h.e.box.Retired[0].LocalID {
			t.Fatalf("status %+v retired %+v", s, h.e.box.Retired)
		}
	}
	check()
	h.restart()
	check()
}

// A list answer over the cap is a clear error, retried at the list period.
func TestListOverCapIsClear(t *testing.T) {
	h := newHarness(t)
	h.api.push(func(Request) (Response, error, bool, bool) { return Response{}, ErrAnswerTooLarge, true, false })
	d := h.e.Step(context.Background())
	if s := h.e.Status(); !strings.Contains(s.LastError, "64 KiB") || d < DefaultListEvery {
		t.Fatalf("delay %v status %+v", d, s)
	}
}

func TestRepairDropsOldServerCalls(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(passList(), timeout())
	h.e.Step(context.Background())
	h.e.Step(context.Background())
	old := h.api.requests(pb.DeviceMethod_REGISTER_APPS)[0].Key
	other := repair(t, h)
	h.settle(20)
	for _, r := range other.calls {
		if r.Key == old {
			t.Fatal("old server's call sent to the new server")
		}
	}
	registeredOn(t, other, 1)
}

func TestAdoptionDisablesOnlyImportedApps(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	a.ServerServiceID = "aaaaaaaa-0000-4000-8000-000000000099"
	h := newHarness(t, a)
	h.settle(20)
	if tg := h.target(a.LocalID); tg == nil || tg.Disabled {
		t.Fatalf("local app disabled: %+v", tg)
	}
	registeredOn(t, h.api, 1)
}
