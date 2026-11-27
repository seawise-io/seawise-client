package pair

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/store"
)

const heldServer = "00000000-0000-4000-8000-00000000aaaa"

// held stores a key-paired account whose key is not this agent's.
func (v *env) held() *store.Account {
	v.t.Helper()
	acc := &store.Account{ServerID: heldServer, ServerName: "nas", APIURL: v.origin, DeviceID: "d0000000-0000-4000-8000-00000000aaaa", KeyID: strings.Repeat("B", 43)}
	err := v.st.Update(func(st *store.State) error {
		st.Account = acc
		st.Targets = append(st.Targets, store.Target{LocalID: jellyfinID, Name: "jellyfin", Host: "127.0.0.1", Port: 8096, Source: store.SourceLocal,
			ServerServiceID: "11111111-1111-4111-8111-111111111111", Subdomain: "jf", ServerPublic: true})
		return nil
	})
	if err != nil {
		v.t.Fatal(err)
	}
	return acc
}

// restart ends the Pairer as a stopping agent does (the code is not
// cancelled) and opens the same directory again.
func (v *env) restart() {
	v.t.Helper()
	v.stopRun()
	v.wait("poller stopped", func() bool {
		at := v.p.running()
		if at == nil {
			return true
		}
		select {
		case <-at.done:
			return true
		default:
			return false
		}
	})
	v.p = nil
	v.close()
	v.open()
}

// settled waits until the pairing is stored and its poller has finished
// cleaning up: "paired" shows as soon as the account is written, before the
// token and the kept code are removed.
func (v *env) settled() {
	v.t.Helper()
	v.wait("paired", v.state(StatePaired))
	v.wait("poller done", func() bool { return v.p.running() == nil && v.kept() == nil })
}

func (v *env) kept() *store.PendingPairing {
	return v.st.Secrets().Pairing
}

func TestReconnectHeldAccount(t *testing.T) {
	v := newEnv(t)
	v.held()
	if _, err := v.p.Start(context.Background(), "nas"); !errors.Is(err, ErrPaired) {
		t.Fatalf("usable account: %v", err)
	}
	if s := v.p.Status(); s.State != StatePaired {
		t.Fatalf("status %+v", s)
	}
	v.reconnect.Store(true)
	if s := v.p.Status(); s.State != StateReconnect || s.ServerName != "nas" {
		t.Fatalf("status %+v", s)
	}
	v.fake.with(func(f *fakePairing) { f.answer[PathComplete] = func(d map[string]any) { d["server_id"] = heldServer } })
	s := v.start()
	if s.State != StatePending || v.p.Status().State != StatePending {
		t.Fatalf("status %+v / %+v", s, v.p.Status())
	}
	k := v.key()
	if rec := v.kept(); rec == nil || rec.KeyID != k.KeyID() || rec.UserCode != s.Code || rec.Origin != v.origin || !rec.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatalf("kept %+v", rec)
	}
	v.fake.approve()
	v.wait("stored", func() bool { a := v.st.State().Account; return a != nil && a.KeyID == k.KeyID() })
	v.reconnect.Store(false)
	v.settled()
	st := v.st.State()
	if st.Account.ServerID != heldServer || st.Account.DeviceID == "" || st.Account.DeviceID == "d0000000-0000-4000-8000-00000000aaaa" {
		t.Fatalf("account %+v", st.Account)
	}
	if tg := st.Targets[0]; tg.Name != "jellyfin" || tg.ServerServiceID != "" || tg.Subdomain != "" || tg.ServerPublic {
		t.Fatalf("target %+v", tg)
	}
	if v.kept() != nil || v.st.Secrets().FRPToken != "" {
		t.Fatal("kept code or token left")
	}
	v.wait("OnPaired", func() bool { return v.paired.Load() == 1 })
	v.noSecrets()
}

func TestReconnectReplacesOnlyTheStartedAccount(t *testing.T) {
	v := newEnv(t)
	v.held()
	v.reconnect.Store(true)
	v.start()
	other := &store.Account{ServerID: "00000000-0000-4000-8000-0000000000ff", DeviceID: "d0000000-0000-4000-8000-0000000000ff", KeyID: strings.Repeat("C", 43)}
	if err := v.st.Update(func(st *store.State) error { st.Account = other; return nil }); err != nil {
		t.Fatal(err)
	}
	v.fake.approve()
	v.wait("ended", v.state(StateFailed))
	if s := v.p.Status(); !strings.Contains(s.Error, "another way") {
		t.Fatalf("status %+v", s)
	}
	if v.st.State().Account.ServerID != other.ServerID || v.kept() != nil {
		t.Fatal("account replaced or code kept")
	}
}

func TestReconnectNoLongerNeeded(t *testing.T) {
	v := newEnv(t)
	acc := v.held()
	v.reconnect.Store(true)
	v.start()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	v.reconnect.Store(false)
	if s := v.p.Status(); s.State != StatePaired {
		t.Fatalf("status %+v", s)
	}
	v.fake.approve()
	v.wait("completed", func() bool { return v.fake.count(PathComplete) >= 1 })
	v.wait("ended", func() bool { return v.p.running() == nil })
	v.p.mu.Lock()
	s := v.p.status
	v.p.mu.Unlock()
	if s.State != StateFailed || !strings.Contains(s.Error, "use its account again") {
		t.Fatalf("status %+v", s)
	}
	if got := v.st.State().Account; got.KeyID != acc.KeyID || got.ServerID != acc.ServerID || v.kept() != nil {
		t.Fatalf("account %+v", got)
	}
}

// An approval the agent never stored is completed after a restart.
func TestKeptCodeResumedAfterRestart(t *testing.T) {
	v := newEnv(t)
	s := v.start()
	k := v.key()
	v.wait("polling", func() bool { return v.fake.count(PathStatus) >= 1 })
	v.restart()
	if rec := v.kept(); rec == nil || rec.UserCode != s.Code {
		t.Fatalf("code not kept: %+v", rec)
	}
	if n := v.fake.count(PathCancel); n != 0 {
		t.Fatal("stopping agent cancelled its code")
	}
	v.fake.approve()
	v.p.Resume()
	if got := v.p.Status(); got.State != StatePending && got.State != StatePaired {
		t.Fatalf("resumed status %+v", got)
	}
	v.settled()
	if acc := v.st.State().Account; acc.KeyID != k.KeyID() || v.kept() != nil || len(v.fake.keyIDs(PathRequest)) != 1 {
		t.Fatalf("account %+v, %d requests", acc, len(v.fake.keyIDs(PathRequest)))
	}
	v.p.Resume()
	if len(v.fake.keyIDs(PathRequest)) != 1 {
		t.Fatal("second resume requested a code")
	}
}

// The server completed the pairing but the answer was lost before the
// agent stored it: the resumed code shows as used and completes again.
func TestKeptCodeCompletedBeforeTheCrash(t *testing.T) {
	v := newEnv(t)
	v.start()
	v.restart()
	v.fake.with(func(f *fakePairing) {
		r := f.last()
		r.status, r.serverID, r.deviceID = "completed", "00000000-0000-4000-8000-00000000bbbb", "d0000000-0000-4000-8000-00000000bbbb"
	})
	v.p.Resume()
	v.settled()
	if acc := v.st.State().Account; acc.ServerID != "00000000-0000-4000-8000-00000000bbbb" {
		t.Fatalf("account %+v", acc)
	}
}

// Start completes an approved kept code instead of asking for a new one.
func TestStartFinishesAnApprovedKeptCode(t *testing.T) {
	v := newEnv(t)
	v.start()
	k := v.key()
	v.restart()
	v.fake.approve()
	s, err := v.p.Start(context.Background(), "nas")
	if err != nil || s.State != StatePaired {
		t.Fatalf("start: %+v %v", s, err)
	}
	if acc := v.st.State().Account; acc == nil || acc.KeyID != k.KeyID() || len(v.fake.keyIDs(PathRequest)) != 1 || v.kept() != nil {
		t.Fatalf("account %+v, %d requests", acc, len(v.fake.keyIDs(PathRequest)))
	}
}

// Start cancels a kept code that is still pending and asks for a new one.
func TestStartCancelsAPendingKeptCode(t *testing.T) {
	v := newEnv(t)
	first := v.start()
	k := v.key()
	v.restart()
	s := v.start()
	if s.Code == first.Code || len(v.fake.keyIDs(PathRequest)) != 2 {
		t.Fatalf("no new code: %+v", s)
	}
	if kids := v.fake.keyIDs(PathCancel); len(kids) != 1 || kids[0] != k.KeyID() {
		t.Fatalf("old code not cancelled with its key: %v", kids)
	}
	if rec := v.kept(); rec == nil || rec.UserCode != s.Code {
		t.Fatalf("kept %+v", rec)
	}
	// An ended kept code is forgotten without a cancel.
	v.restart()
	v.fake.setStatus("expired")
	s = v.start()
	if n := len(v.fake.keyIDs(PathCancel)); n != 1 || len(v.fake.keyIDs(PathRequest)) != 3 || v.kept().UserCode != s.Code {
		t.Fatalf("%d cancels", n)
	}
}

func TestKeptCodeDropped(t *testing.T) {
	cases := map[string]func(v *env, rec *store.PendingPairing){
		"expired":      func(v *env, _ *store.PendingPairing) { v.clk.add(16 * time.Minute) },
		"other key":    func(_ *env, rec *store.PendingPairing) { rec.KeyID = strings.Repeat("A", 43) },
		"bad device":   func(_ *env, rec *store.PendingPairing) { rec.DeviceCode = "x" },
		"bad user":     func(_ *env, rec *store.PendingPairing) { rec.UserCode = "abc" },
		"http origin":  func(_ *env, rec *store.PendingPairing) { rec.Origin = "http://api.seawise.io" },
		"no expiry":    func(_ *env, rec *store.PendingPairing) { rec.ExpiresAt = time.Time{} },
		"paired":       func(v *env, _ *store.PendingPairing) { v.held() },
		"no key":       func(v *env, _ *store.PendingPairing) { _ = v.ks.Close() },
		"already kept": nil,
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v := newEnv(t)
			v.start()
			v.restart()
			if name == "already kept" {
				v.fake.approve()
				v.p.Resume()
				v.settled()
				if err := v.st.UpdateSecrets(func(s *store.Secrets) error {
					// Another code than the finished attempt's, so its poller cannot be the one removing it.
					s.Pairing = &store.PendingPairing{DeviceCode: strings.Repeat("f", 32), UserCode: v.fake.last().user, Origin: v.origin,
						KeyID: v.key().KeyID(), ExpiresAt: v.clk.now().Add(time.Minute)}
					s.FRPToken = v1Token
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				v.p.Resume()
				if v.kept() != nil || v.st.Secrets().FRPToken != "" {
					t.Fatal("stored pairing's leftovers kept")
				}
				return
			}
			rec := *v.kept()
			change(v, &rec)
			if err := v.st.UpdateSecrets(func(s *store.Secrets) error { s.Pairing = &rec; return nil }); err != nil {
				t.Fatal(err)
			}
			v.p.Resume()
			if v.p.running() != nil || v.kept() != nil {
				t.Fatalf("%s resumed", name)
			}
		})
	}
}

// A request answer the agent refuses has its code cancelled when the
// answer names one.
func TestRefusedRequestAnswerIsCancelled(t *testing.T) {
	cases := map[string]struct {
		fn     func(map[string]any)
		cancel int
	}{
		"other key":     {func(d map[string]any) { d["key_id"] = strings.Repeat("A", 43) }, 1},
		"extra member":  {func(d map[string]any) { d["frp_token"] = "x" }, 1},
		"bad user code": {func(d map[string]any) { d["user_code"] = "x" }, 1},
		"bad device":    {func(d map[string]any) { d["device_code"] = "x" }, 0},
		"number device": {func(d map[string]any) { d["device_code"] = 5 }, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v := newEnv(t)
			v.fake.with(func(f *fakePairing) { f.answer[PathRequest] = c.fn })
			if _, err := v.p.Start(context.Background(), "nas"); err == nil {
				t.Fatal("answer accepted")
			}
			if kids := v.fake.keyIDs(PathCancel); len(kids) != c.cancel || (c.cancel == 1 && kids[0] != v.key().KeyID()) {
				t.Fatalf("cancels %v", kids)
			}
			if c.cancel == 1 && v.fake.last().status != "cancelled" {
				t.Fatalf("code %s", v.fake.last().status)
			}
			if v.kept() != nil {
				t.Fatal("refused code kept")
			}
		})
	}
}

func TestDeviceCodeOf(t *testing.T) {
	const dc = "0123456789abcdef0123456789abcdef"
	for raw, want := range map[string]string{
		`{"data":{"device_code":"` + dc + `"}}`:                  dc,
		`{"data":{"device_code":"` + dc + `","x":1},"y":2}`:      dc,
		`{"data":{"device_code":"` + strings.ToUpper(dc) + `"}}`: "",
		`{"data":{"device_code":5}}`:                             "",
		`{"data":{}}`:                                            "",
		`not json`:                                               "",
		`{"data":{"device_code":"` + dc + `"}} trailing`:         "",
		`{"data":{"device_code":"` + dc + `","p":"` + strings.Repeat("x", 4<<10) + `"}}`: "",
	} {
		if got := deviceCodeOf([]byte(raw)); got != want {
			t.Errorf("%.60s: %q", raw, got)
		}
	}
}

func FuzzDeviceCodeOf(f *testing.F) {
	f.Add([]byte(`{"data":{"device_code":"0123456789abcdef0123456789abcdef"}}`))
	f.Add([]byte(`{"data":{"device_code":"0123456789abcdef0123456789abcdeF"}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if got := deviceCodeOf(raw); got != "" && !deviceCodeRe.MatchString(got) {
			t.Fatalf("%q", got)
		}
	})
}

// An imported 1.x account held for a new pairing keeps its token until the
// new account is stored, then loses it.
func TestReconnectImportedAccount(t *testing.T) {
	dir := t.TempDir()
	writeV1(t, dir, "https://api.seawise.io")
	v := newEnvDir(t, dir)
	v.reconnect.Store(true)
	v.fake.with(func(f *fakePairing) { f.answer[PathComplete] = func(d map[string]any) { d["server_id"] = v1Server } })
	v.start()
	if v.st.Secrets().FRPToken != v1Token {
		t.Fatal("token dropped before the new account is stored")
	}
	k := v.key()
	v.fake.approve()
	v.wait("stored", func() bool { a := v.st.State().Account; return a != nil && a.KeyID == k.KeyID() })
	v.wait("token removed", func() bool { return v.st.Secrets().FRPToken == "" && v.kept() == nil })
	if acc := v.st.State().Account; acc.ServerID != v1Server || !acc.Keyed() {
		t.Fatalf("account %+v", acc)
	}
}
