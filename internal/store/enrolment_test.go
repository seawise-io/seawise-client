package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openGroupB(t *testing.T) (*Store, string) {
	t.Helper()
	dir := copyV1Fixture(t, "B")
	s, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestEnrolmentNeededAfterImport(t *testing.T) {
	s, _ := openGroupB(t)
	if !s.State().EnrolmentNeeded(s.Secrets()) {
		t.Fatal("imported v1 account should need enrolment")
	}
	if err := s.Update(func(st *State) error {
		st.Enrolment = &Enrolment{ServerID: testServerID, Phase: PhasePending, StartedAt: fixedNow}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !s.State().EnrolmentNeeded(s.Secrets()) {
		t.Fatal("pending enrolment is still needed")
	}
}

func TestEnrolmentNotNeededWithoutAccount(t *testing.T) {
	s, err := Open(t.TempDir(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.State().EnrolmentNeeded(s.Secrets()) {
		t.Fatal("fresh install needs no enrolment")
	}
}

func TestSwitchedAccountMayDropToken(t *testing.T) {
	s, dir := openGroupB(t)
	now := fixedNow.Add(time.Minute)
	if err := s.UpdateSecrets(func(sec *Secrets) error { sec.FRPToken = ""; return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token cleared before the switch: %v", err)
	}
	if err := s.Update(func(st *State) error {
		st.Enrolment = &Enrolment{ServerID: testServerID, Phase: PhaseSwitched, KeyID: "kid-aaaaaaaaaaaaaaaaaaaaaa", StartedAt: fixedNow, SwitchedAt: &now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if s.State().EnrolmentNeeded(s.Secrets()) {
		t.Fatal("switched enrolment is not needed")
	}
	if err := s.UpdateSecrets(func(sec *Secrets) error { sec.FRPToken = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(dir, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Secrets().FRPToken != "" || s2.State().Account == nil || s2.State().Enrolment.Phase != PhaseSwitched {
		t.Fatal("switched state did not survive reopen")
	}
}

func TestSwitchedForAnotherServerKeepsTokenRequired(t *testing.T) {
	s, _ := openGroupB(t)
	if err := s.Update(func(st *State) error {
		st.Enrolment = &Enrolment{ServerID: "00000000-0000-4000-8000-0000000000b2", Phase: PhaseSwitched, KeyID: "k", StartedAt: fixedNow}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !s.State().EnrolmentNeeded(s.Secrets()) {
		t.Fatal("a record for another server does not cover this account")
	}
	if err := s.UpdateSecrets(func(sec *Secrets) error { sec.FRPToken = ""; return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token cleared under another server's record: %v", err)
	}
}

func TestEnrolmentValidation(t *testing.T) {
	s, _ := openGroupB(t)
	bad := []Enrolment{
		{ServerID: testServerID, Phase: "done", StartedAt: fixedNow},
		{ServerID: "", Phase: PhasePending, StartedAt: fixedNow},
		{ServerID: testServerID, Phase: PhaseEnrolled, StartedAt: fixedNow},
		{ServerID: testServerID, Phase: PhaseSwitched, StartedAt: fixedNow},
		{ServerID: testServerID, Phase: PhasePending, StartedAt: fixedNow, Hold: "made_up"},
	}
	for i, e := range bad {
		e := e
		if err := s.Update(func(st *State) error { st.Enrolment = &e; return nil }); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	ok := Enrolment{ServerID: testServerID, Phase: PhaseEnrolled, KeyID: "k", StartedAt: fixedNow, Hold: HoldKeyRevoked}
	if err := s.Update(func(st *State) error { st.Enrolment = &ok; return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestEnrolmentIsCopied(t *testing.T) {
	s, _ := openGroupB(t)
	now := fixedNow
	if err := s.Update(func(st *State) error {
		st.Enrolment = &Enrolment{ServerID: testServerID, Phase: PhasePending, StartedAt: fixedNow, HoldAt: &now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st := s.State()
	st.Enrolment.Phase = PhaseSwitched
	*st.Enrolment.HoldAt = time.Time{}
	if got := s.State().Enrolment; got.Phase != PhasePending || got.HoldAt.IsZero() {
		t.Fatal("State returned shared enrolment")
	}
}

// FuzzImportAccount feeds arbitrary 1.x account files through the import:
// it never panics, and an imported account always needs enrolment with
// exactly the token the file holds.
func FuzzImportAccount(f *testing.F) {
	f.Add([]byte(`{"server_id":"` + testServerID + `","frp_token":"` + strings.Repeat("ab", 32) + `","api_url":"https://api.seawise.io"}`))
	f.Add([]byte(`{"server_id":"x","frp_token":"y","frp_token":"z"}`))
	f.Add([]byte(`{"server_id":"x","frp_token":""}`))
	f.Add([]byte(`{"SERVER_ID":"x","Frp_Token":"y","extra":[1,2]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "account.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir, clock)
		if err != nil {
			return
		}
		defer s.Close()
		st, sec := s.State(), s.Secrets()
		if st.Account == nil {
			if st.EnrolmentNeeded(sec) {
				t.Fatal("enrolment without an account")
			}
			return
		}
		var want struct {
			FRPToken string `json:"frp_token"`
		}
		if err := json.Unmarshal(b, &want); err != nil || want.FRPToken != sec.FRPToken || sec.FRPToken == "" {
			t.Fatal("imported token differs from the file")
		}
		if !st.EnrolmentNeeded(sec) || st.Enrolment != nil {
			t.Fatal("imported account does not need enrolment")
		}
	})
}
