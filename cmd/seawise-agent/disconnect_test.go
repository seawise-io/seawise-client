package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/seawise/client/internal/adminui"
	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

type fakeSender struct {
	answer devicecall.Answer
	err    error
	got    []devicecall.Request
}

func (f *fakeSender) Send(_ context.Context, r devicecall.Request) (devicecall.Answer, error) {
	f.got = append(f.got, r)
	return f.answer, f.err
}

// keyedStore is a store paired with the device key, with two apps known to the server.
func keyedStore(t *testing.T) (*store.Store, identity.Keystore, string) {
	t.Helper()
	st, ks := importedStore(t)
	k, err := ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err = st.Update(func(s *store.State) error {
		s.Account = &store.Account{ServerID: "6f1d2c3b-4a59-4687-9a1b-2c3d4e5f6a7b", ServerName: "nas", APIURL: "https://api.seawise.io",
			DeviceID: "d0000000-0000-4000-8000-000000000001", KeyID: k.KeyID()}
		s.Enrolment = nil
		s.Targets = []store.Target{
			{LocalID: "a", Name: "Media", Host: "192.168.1.2", Port: 8096, ServerServiceID: "s1", Subdomain: "media", ServerPublic: true, Source: store.SourceLocal},
			{LocalID: "b", Name: "Notes", Host: "192.168.1.3", Port: 3000, ServerServiceID: "s2", Subdomain: "notes", ServerDisableRequestedAt: &now, Source: store.SourceLocal},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecrets(func(s *store.Secrets) error { s.FRPToken = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	return st, ks, k.KeyID()
}

func checkForgotten(t *testing.T, st *store.Store) {
	t.Helper()
	s := st.State()
	if s.Account != nil || s.Enrolment != nil || st.Secrets().FRPToken != "" || st.Secrets().Pairing != nil {
		t.Fatalf("account kept: %+v %+v", s.Account, s.Enrolment)
	}
	if len(s.Targets) != 2 {
		t.Fatalf("apps lost: %+v", s.Targets)
	}
	for _, tg := range s.Targets {
		if tg.ServerServiceID != "" || tg.Subdomain != "" || tg.ServerDisableRequestedAt != nil || tg.ServerPublic || tg.Host == "" {
			t.Fatalf("app keeps server state: %+v", tg)
		}
	}
}

func TestDisconnectKeyed(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer devicecall.Answer
		err    error
		told   bool
	}{
		{"unpaired", devicecall.Answer{Status: 200, Body: []byte(`{"result":"unpaired"}`)}, nil, true},
		{"already removed", devicecall.Answer{Status: 401, Body: []byte(`{"error":"invalid_proof","code":"invalid_proof"}`)}, nil, true},
		{"key revoked", devicecall.Answer{Status: 401, Body: []byte(`{"error":"invalid_proof","code":"key_revoked"}`)}, nil, true},
		{"replayed", devicecall.Answer{Status: 401, Body: []byte(`{"error":"invalid_proof","code":"replayed"}`)}, nil, false},
		{"unavailable", devicecall.Answer{Status: 503, Body: []byte(`{"error":"Service unavailable"}`)}, nil, false},
		{"offline", devicecall.Answer{}, errors.New("dial tcp: connection refused"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			st, ks, kid := keyedStore(t)
			send := &fakeSender{answer: c.answer, err: c.err}
			reconciled, cancelled, legacy := 0, 0, 0
			d := &disconnector{log: slog.Default(), st: st, keys: ks, call: send,
				legacy:        func(context.Context, string) error { legacy++; return nil },
				legacyAllowed: func(store.State) bool { return true },
				cancelPairing: func() { cancelled++ },
				reconcile:     func(context.Context) error { reconciled++; return nil }}
			got, err := d.Disconnect(context.Background())
			if err != nil || got.Told != c.told {
				t.Fatalf("got %+v %v, want told %v", got, err, c.told)
			}
			if len(send.got) != 1 {
				t.Fatalf("%d device calls", len(send.got))
			}
			r := send.got[0]
			if r.Method != http.MethodPost || r.Path != "/device/v2/disconnect" || r.Origin != "https://api.seawise.io" || len(r.Body) != 0 {
				t.Fatalf("request %s %s%s %q", r.Method, r.Origin, r.Path, r.Body)
			}
			if k, ok := r.Key.(*identity.Key); !ok || k.KeyID() != kid {
				t.Fatalf("signed with %v", r.Key)
			}
			if legacy != 0 || reconciled != 1 || cancelled != 1 {
				t.Fatalf("legacy %d, reconcile %d, cancel %d", legacy, reconciled, cancelled)
			}
			checkForgotten(t, st)
			if k, err := ks.Current(); err != nil || k.KeyID() == kid {
				t.Fatalf("device key kept: %v", err)
			}
		})
	}
}

func TestDisconnectLegacyToken(t *testing.T) {
	const serverID = "6f1d2c3b-4a59-4687-9a1b-2c3d4e5f6a7b"
	for _, c := range []struct {
		allowed bool
		err     error
		told    bool
	}{{true, nil, true}, {true, errors.New("502"), false}, {false, nil, false}} {
		st, ks := importedStore(t)
		var got []string
		send := &fakeSender{}
		d := &disconnector{log: slog.Default(), st: st, keys: ks, call: send,
			legacy:        func(_ context.Context, id string) error { got = append(got, id); return c.err },
			legacyAllowed: func(store.State) bool { return c.allowed }}
		r, err := d.Disconnect(context.Background())
		if err != nil || r.Told != c.told || len(send.got) != 0 {
			t.Fatalf("%+v: %+v %v, %d device calls", c, r, err, len(send.got))
		}
		if c.allowed && (len(got) != 1 || got[0] != serverID) {
			t.Fatalf("legacy calls %v", got)
		}
		if !c.allowed && len(got) != 0 {
			t.Fatal("token used after enrolment")
		}
		if s := st.State(); s.Account != nil || st.Secrets().FRPToken != "" {
			t.Fatal("account kept")
		}
	}
}

func TestDisconnectNotPaired(t *testing.T) {
	st, ks, _ := keyedStore(t)
	if err := st.Update(func(s *store.State) error { s.Account = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	send := &fakeSender{}
	d := &disconnector{log: slog.Default(), st: st, keys: ks, call: send}
	if _, err := d.Disconnect(context.Background()); !errors.Is(err, adminui.ErrNotPaired) || len(send.got) != 0 {
		t.Fatalf("unpaired: %v, %d calls", err, len(send.got))
	}
}
