package updatecheck

import "testing"

// Hiding release notices never stops the key set from being fetched.
func TestHiddenNoticesStillFetchTheKeySet(t *testing.T) {
	f := newFixture(t)
	var got []byte
	c := f.checker(stateDir(t), func(cfg *Config) {
		cfg.HideNotices = true
		cfg.OnKeySet = func(b []byte) { got = b }
	})
	mustCheck(t, c)
	if string(got) != keysetV1 || string(c.KeySet()) != keysetV1 {
		t.Fatalf("key set %q", got)
	}
	if st := c.Status(); st.Available != nil || st.State != StateOK {
		t.Fatalf("status %+v", st)
	}
	if !c.Fresh(t0) {
		t.Fatal("hidden notices changed freshness")
	}
}
