package appsync

import (
	"context"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// forge answers every relayed call of method m with resp.
func forge(h *harness, m pb.DeviceMethod, resp Response) {
	h.api.mu.Lock()
	h.api.relayed = true
	h.api.forge = func(r Request) (Response, bool) { return resp, r.Method == m }
	h.api.mu.Unlock()
}

func setDirectDown(h *harness, down bool) {
	h.api.mu.Lock()
	h.api.directDown = down
	h.api.mu.Unlock()
}

func directCalls(f *fakeAPI, m pb.DeviceMethod, key string) int {
	n := 0
	for _, r := range f.requests(m) {
		if r.Direct && r.Key == key {
			n++
		}
	}
	return n
}

// A relayed refusal of a queued register never drops it: the same call
// goes directly, and only that answer is acted on.
func TestRelayedRefusalsConfirmedDirectly(t *testing.T) {
	for name, forged := range map[string]Response{
		"refused":              jsonResp(403, map[string]string{"error": "limit_reached"}),
		"bad request":          jsonResp(400, map[string]string{"error": "invalid_request"}),
		"idempotency mismatch": jsonResp(409, map[string]string{"error": "idempotency_mismatch"}),
		"name taken":           jsonResp(409, map[string]any{"error": "name_taken", "index": 0}),
	} {
		t.Run(name, func(t *testing.T) {
			a := app("A", "10.0.0.1", 80)
			h := newHarness(t, a)
			forge(h, pb.DeviceMethod_REGISTER_APPS, forged)
			setDirectDown(h, true)
			h.steps(3)
			s := h.e.Status()
			if s.OutboxDepth != 1 || len(s.Refused) != 0 {
				t.Fatalf("relayed refusal acted on: %+v", s)
			}
			key := h.e.box.Calls[0].Key
			setDirectDown(h, false)
			h.settle(20)
			registeredOn(t, h.api, 1)
			if h.target(a.LocalID).ServerServiceID == "" || directCalls(h.api, pb.DeviceMethod_REGISTER_APPS, key) == 0 {
				t.Fatal("register not confirmed directly under its key")
			}
			if h.api.executed[key] != 1 {
				t.Fatalf("register ran %d times", h.api.executed[key])
			}
		})
	}
}

// A relayed delete success is confirmed directly before the call is
// dropped and the registration forgotten.
func TestRelayedDeleteSuccessConfirmedDirectly(t *testing.T) {
	a, b := app("A", "10.0.0.1", 80), app("B", "10.0.0.2", 81)
	h := newHarness(t, a, b)
	h.settle(20)
	forge(h, pb.DeviceMethod_DELETE_APPS, jsonResp(200, map[string]any{"items": []any{}}))
	setDirectDown(h, true)
	if err := h.e.Remove(a.LocalID); err != nil {
		t.Fatal(err)
	}
	h.steps(3)
	if h.e.Status().OutboxDepth != 1 || len(h.api.live()) != 2 {
		t.Fatalf("relayed delete answer dropped the call: %+v", h.e.Status())
	}
	key := h.e.box.Calls[0].Key
	setDirectDown(h, false)
	h.settle(20)
	if len(h.api.live()) != 1 || directCalls(h.api, pb.DeviceMethod_DELETE_APPS, key) == 0 || h.e.Status().OutboxDepth != 0 {
		t.Fatalf("delete not confirmed directly: %+v", h.api.live())
	}
}

// A plain relayed register success is acted on without a direct call.
func TestRelayedRegisterSuccessNeedsNoDirectCall(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.api.mu.Lock()
	h.api.relayed = true
	h.api.mu.Unlock()
	h.settle(20)
	registeredOn(t, h.api, 1)
	for _, r := range h.api.requests(pb.DeviceMethod_REGISTER_APPS) {
		if r.Direct {
			t.Fatal("direct register for a plain success")
		}
	}
}

// A relayed register answer that names another server app for a removed
// app (which would cancel its delete) is confirmed directly.
func TestRelayedAdoptionOfAnotherAppNeedsDirect(t *testing.T) {
	h := newHarness(t)
	lid := NewLocalID()
	h.e.box.Retired = []Retired{{LocalID: lid, ServerID: "aaaaaaaa-0000-4000-8000-000000000001"}}
	c := Call{Op: OpRegister, LocalIDs: []string{lid}}
	answerAs := func(id, result string) Response {
		return jsonResp(200, map[string]any{"items": []any{map[string]any{"local_id": lid, "id": id, "result": result, "subdomain": "brave-otter"}}})
	}
	answer := func(id string) Response { return answerAs(id, resUnchanged) }
	for _, res := range []string{resUpdated, resUnchanged} {
		if !h.e.needsDirect(c, answerAs("aaaaaaaa-0000-4000-8000-000000000002", res)) {
			t.Fatal(res, "other server app taken from a relayed answer")
		}
	}
	if h.e.needsDirect(c, answerAs("aaaaaaaa-0000-4000-8000-000000000002", resCreated)) {
		t.Fatal("a created app needs no direct call")
	}
	if h.e.needsDirect(c, answer("aaaaaaaa-0000-4000-8000-000000000001")) {
		t.Fatal("the same app needs no direct call")
	}
	for _, st := range []int{200, 401, 408, 429, 503} {
		if h.e.needsDirect(Call{Op: OpRegister, LocalIDs: []string{lid}}, Response{Status: st}) {
			t.Fatal(st, "needs a direct call")
		}
	}
	if !h.e.needsDirect(Call{Op: OpDelete}, Response{Status: 200}) || !h.e.needsDirect(Call{Op: OpRegister}, Response{Status: 404}) {
		t.Fatal("delete success or refusal taken from a relayed answer")
	}
}

// A queued call older than the dedupe window is dropped and derived again
// under a new key.
func TestOldQueuedCallDerivedAgain(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.steps(1)
	h.api.push(fail503())
	h.steps(1)
	if h.e.Status().OutboxDepth != 1 {
		t.Fatalf("%+v", h.e.Status())
	}
	old := h.e.box.Calls[0].Key
	h.clk.Add(MaxCallAge + time.Minute)
	h.settle(20)
	apps := registeredOn(t, h.api, 1)
	if apps[0].LocalID != a.LocalID || h.api.executed[old] != 0 {
		t.Fatalf("old key reused: ran %d", h.api.executed[old])
	}
	if s := h.e.Status(); s.OutboxDepth != 0 {
		t.Fatalf("%+v", s)
	}
}

// A call exactly at the age limit is still sent under its key.
func TestCallAtTheAgeLimitKeepsItsKey(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.steps(1)
	h.api.push(fail503())
	h.steps(1)
	key := h.e.box.Calls[0].Key
	h.clk.Add(MaxCallAge - h.clk.Now().Sub(h.e.box.Calls[0].CreatedAt))
	h.e.waitUntil = time.Time{}
	h.e.Step(context.Background())
	if h.api.executed[key] != 1 {
		t.Fatalf("call at the age limit not sent under its key (ran %d)", h.api.executed[key])
	}
}

// A direct resend answered as relayed (a broken carrier) is an unknown
// outcome: the call stays queued.
func TestDirectResendMustBeDirect(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	forge(h, pb.DeviceMethod_REGISTER_APPS, jsonResp(403, map[string]string{"error": "limit_reached"}))
	h.api.mu.Lock()
	h.api.directRelayed = true
	h.api.mu.Unlock()
	h.steps(3)
	if s := h.e.Status(); s.OutboxDepth != 1 || len(s.Refused) != 0 {
		t.Fatalf("relayed answer to a direct call acted on: %+v", s)
	}
}

// After a failed direct confirmation the next one waits a list period,
// and relayed lists keep running meanwhile.
func TestFailedConfirmationWaitsAListPeriod(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	h.api.mu.Lock()
	h.api.relayed, h.api.directDown = true, true
	h.api.mu.Unlock()
	h.api.ownerDelete(a.LocalID)
	h.clk.Add(DefaultListEvery)
	start := h.clk.Now()
	direct, relayed := 0, 0
	for range 40 {
		h.clk.Add(h.e.Step(context.Background()))
		direct, relayed = 0, 0
		for _, r := range h.api.requests(pb.DeviceMethod_LIST_APPS) {
			if r.Direct {
				direct++
			} else {
				relayed++
			}
		}
		if limit := 1 + int(h.clk.Now().Sub(start)/DefaultListEvery); direct > limit {
			t.Fatalf("%d direct lists in %s", direct, h.clk.Now().Sub(start))
		}
	}
	if direct < 2 || relayed < direct {
		t.Fatalf("direct %d relayed %d", direct, relayed)
	}
	if h.target(a.LocalID) == nil {
		t.Fatal("relayed list removed the app")
	}
}

// Relayed 1xx and 3xx answers never drop or refuse the head call.
func TestRelayedInformationalAndRedirectKeepTheCall(t *testing.T) {
	for _, st := range []int{100, 103, 307, 308} {
		a := app("A", "10.0.0.1", 80)
		h := newHarness(t, a)
		forge(h, pb.DeviceMethod_REGISTER_APPS, jsonResp(st, map[string]string{"error": "x"}))
		setDirectDown(h, true)
		h.steps(4)
		if s := h.e.Status(); s.OutboxDepth != 1 || len(s.Refused) != 0 {
			t.Fatalf("%d: head call dropped or refused: %+v", st, s)
		}
		h.api.mu.Lock()
		h.api.forge = nil
		h.api.mu.Unlock()
		setDirectDown(h, false)
		h.clk.Add(DefaultListEvery)
		h.settle(20)
		registeredOn(t, h.api, 1)
	}
	if !transientStatus(100) || !transientStatus(199) || transientStatus(200) {
		t.Fatal("1xx is an unknown outcome")
	}
}

func setPublic(h *harness, lid string, on bool) {
	h.api.mu.Lock()
	for _, a := range h.api.apps {
		if a.LocalID == lid {
			a.Public = on
		}
	}
	h.api.mu.Unlock()
}

// A relayed list may take public access away but never grant it; a direct
// list does.
func TestRelayedListNeverGrantsPublic(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	setPublic(h, a.LocalID, true)
	h.api.mu.Lock()
	h.api.relayed, h.api.directDown = true, true
	h.api.mu.Unlock()
	h.clk.Add(DefaultListEvery)
	h.steps(5)
	if h.target(a.LocalID).ServerPublic || !anyDirectList(h.api) {
		t.Fatal("relayed list granted public access, or no direct list asked")
	}
	setDirectDown(h, false)
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	if !h.target(a.LocalID).ServerPublic {
		t.Fatal("direct list did not grant public access")
	}
	setPublic(h, a.LocalID, false)
	setDirectDown(h, true)
	h.clk.Add(DefaultListEvery)
	h.steps(3)
	if h.target(a.LocalID).ServerPublic {
		t.Fatal("relayed list did not take public access away")
	}
}

// A name_taken relink takes another app's local_id: only from a direct list.
func TestRelinkOnlyFromADirectList(t *testing.T) {
	a := app("Media", "10.0.0.1", 80)
	h := newHarness(t, a)
	listed := NewLocalID()
	l := listAnswer{Apps: []ServerApp{{ID: "aaaaaaaa-0000-4000-8000-000000000001", LocalID: listed, Name: "Media", Host: "10.0.0.1", Port: 80, Subdomain: "media"}}}
	h.e.mu.Lock()
	h.e.relinks = []relink{{localID: a.LocalID, name: "Media"}}
	err := h.e.applyList(l, false, h.clk.Now(), true)
	relinks, confirm := len(h.e.relinks), h.e.confirm
	h.e.mu.Unlock()
	if err != nil || h.target(a.LocalID) == nil || h.target(listed) != nil || relinks != 1 || !confirm {
		t.Fatalf("relayed list relinked (err %v, kept %d, confirm %v)", err, relinks, confirm)
	}
	h.e.mu.Lock()
	err = h.e.applyList(l, false, h.clk.Now(), false)
	h.e.mu.Unlock()
	if err != nil || h.target(listed) == nil {
		t.Fatal("direct list did not relink", err)
	}
}

// With HTTPS blocked, the head call's direct resend is retried a list
// period apart after 3 failures in a row; a direct success resets that.
func TestBlockedDirectResendWaitsAListPeriod(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	forge(h, pb.DeviceMethod_REGISTER_APPS, jsonResp(403, map[string]string{"error": "limit_reached"}))
	setDirectDown(h, true)
	var waits []time.Duration
	firstLong := -1
	for range 8 {
		d := h.e.Step(context.Background())
		if d == DefaultListEvery && firstLong < 0 && h.e.Status().OutboxDepth == 1 {
			firstLong = directCalls(h.api, pb.DeviceMethod_REGISTER_APPS, h.e.box.Calls[0].Key)
		}
		if directCalls(h.api, pb.DeviceMethod_REGISTER_APPS, "") > 0 {
			t.Fatal("direct call without the key")
		}
		waits = append(waits, d)
		h.clk.Add(d)
	}
	key := h.e.box.Calls[0].Key
	n := directCalls(h.api, pb.DeviceMethod_REGISTER_APPS, key)
	if firstLong != maxDirectFails {
		t.Fatalf("waited a list period after %d direct failures", firstLong)
	}
	if n < 3 || waits[len(waits)-1] != DefaultListEvery {
		t.Fatalf("%d direct resends, waits %v", n, waits)
	}
	h.e.mu.Lock()
	fails := h.e.directFails
	h.e.mu.Unlock()
	if fails < 3 {
		t.Fatal(fails)
	}
	setDirectDown(h, false)
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	h.e.mu.Lock()
	fails = h.e.directFails
	h.e.mu.Unlock()
	if fails != 0 || h.e.Status().OutboxDepth != 0 {
		t.Fatal("direct success did not reset", fails)
	}
}
