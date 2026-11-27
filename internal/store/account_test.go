package store

import (
	"errors"
	"strings"
	"testing"
)

const (
	testDeviceID = "00000000-0000-4000-8000-0000000000d1"
	testKeyID    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	pairedServer = "00000000-0000-4000-8000-0000000000b2"
)

func keyedAccount() *Account {
	return &Account{ServerID: pairedServer, APIURL: "https://api.seawise.io", DeviceID: testDeviceID, KeyID: testKeyID}
}

func TestKeyedAccountNeedsNoToken(t *testing.T) {
	base := t.TempDir()
	s, err := Open(base, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error { st.Account = &Account{ServerID: pairedServer}; return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("account without token or key accepted: %v", err)
	}
	if err := s.Update(func(st *State) error { st.Account = keyedAccount(); return nil }); err != nil {
		t.Fatal(err)
	}
	st := s.State()
	if st.EnrolmentNeeded(s.Secrets()) || !st.Account.Keyed() || (&Account{ServerID: pairedServer}).Keyed() {
		t.Fatal("keyed account needs enrolment")
	}
	s.Close()
	s, err = Open(base, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if a := s.State().Account; a == nil || a.KeyID != testKeyID || a.DeviceID != testDeviceID {
		t.Fatalf("account not kept: %+v", a)
	}
}

func TestKeyedAccountValidation(t *testing.T) {
	bad := []func(a *Account){
		func(a *Account) { a.KeyID = "" },
		func(a *Account) { a.DeviceID = "" },
		func(a *Account) { a.KeyID = testKeyID[:42] },
		func(a *Account) { a.KeyID = testKeyID + "A" },
		func(a *Account) { a.KeyID = strings.Repeat("+", 43) },
		func(a *Account) { a.KeyID = strings.Repeat("=", 43) },
		func(a *Account) { a.DeviceID = "not-a-uuid" },
		func(a *Account) { a.DeviceID = strings.ToUpper(testDeviceID) },
	}
	for i, f := range bad {
		s, err := Open(t.TempDir(), clock)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Update(func(st *State) error { a := keyedAccount(); f(a); st.Account = a; return nil }); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
		s.Close()
	}
	s, err := Open(t.TempDir(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Update(func(st *State) error {
		a := keyedAccount()
		a.KeyID = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ-_01234"
		st.Account = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyedAccountIsNotBackfilledAsImport(t *testing.T) {
	dir := copyV1Fixture(t, "B")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error { st.Import.ServerID, st.Account = "", keyedAccount(); return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.State().Import.ServerID; got != "" {
		t.Fatalf("paired server recorded as the imported one: %q", got)
	}
}
