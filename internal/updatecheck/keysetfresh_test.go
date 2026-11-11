package updatecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

func keySetPath(b []byte) string {
	s := sha256.Sum256(b)
	return "/targets/" + hex.EncodeToString(s[:]) + ".keyset.json"
}

// Fresh metadata that lists a key set the agent does not hold is not fresh:
// otherwise a revoked control key could keep signing instructions.
func TestFreshNeedsTheListedKeySet(t *testing.T) {
	f := newFixture(t)
	c := f.checker(stateDir(t))
	mustCheck(t, c)
	if !c.Fresh(t0) {
		t.Fatal("not fresh after a clean check")
	}
	next := []byte(`{"keys":["two"]}`)
	f.publish(map[string][]byte{"keyset.json": next}, t0.Add(time.Hour))
	f.serve(keySetPath(next), func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	f.setNow(t0.Add(2 * time.Hour))
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("check with a missing key set passed")
	}
	if c.Fresh(t0.Add(2 * time.Hour)) {
		t.Fatal("fresh while the listed key set was not fetched")
	}
	f.serve(keySetPath(next), nil)
	mustCheck(t, c)
	if !c.Fresh(t0.Add(2 * time.Hour)) {
		t.Fatal("not fresh once the listed key set is held")
	}
}

func TestFreshNeedsTheKeySetAccepted(t *testing.T) {
	f := newFixture(t)
	accepted := ""
	c := f.checker(stateDir(t), func(cfg *Config) {
		cfg.AcceptedKeySet = func() string { return accepted }
	})
	mustCheck(t, c)
	if c.Fresh(t0) {
		t.Fatal("fresh while the key set manager refused the listed set")
	}
	s := sha256.Sum256([]byte(keysetV1))
	accepted = hex.EncodeToString(s[:])
	if !c.Fresh(t0) {
		t.Fatal("not fresh with the listed set accepted")
	}
}
