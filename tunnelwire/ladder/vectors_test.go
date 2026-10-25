package ladder

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/seawise-io/seawise-client/tunnelwire/internal/vkeys"
)

func TestVectorsUpToDate(t *testing.T) {
	ok, err := vkeys.Sync("ladder.json", vkeys.Pretty(genLadder()), os.Getenv("UPDATE_VECTORS") == "1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("ladder.json is out of date; run with UPDATE_VECTORS=1")
	}
}

func loadLadder(t *testing.T) lfile {
	b, err := vkeys.Load("ladder.json")
	if err != nil {
		t.Fatal(err)
	}
	var f lfile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLadderVectors(t *testing.T) {
	for _, c := range loadLadder(t).Cases {
		m := New(c.Initial.State, c.Initial.Generation, c.Initial.ModeOn)
		for i, s := range c.Steps {
			got, _ := json.Marshal(m.Step(s.Event))
			want, _ := json.Marshal(s.Want)
			if !bytes.Equal(got, want) {
				t.Errorf("%s step %d (%s): got %s, want %s", c.Name, i, s.Event.Kind, got, want)
				break
			}
		}
	}
}

// Every case keeps the protections: no HOLD or V1 without a signed state
// event (or a local repair fact) in the same step, and no V1 entry after a
// transport failure alone.
func TestLadderProtections(t *testing.T) {
	for _, c := range loadLadder(t).Cases {
		prev := c.Initial.State
		for i, s := range c.Steps {
			st := s.Want.State
			if st != prev && (st == Hold || st == V1) {
				ok := s.Event.Kind == EvSignedState || s.Event.Kind == EvRepair || s.Event.Kind == EvFRPCRefused && s.Event.Authenticated
				if !ok {
					t.Errorf("%s step %d: %s entered on %s", c.Name, i, st, s.Event.Kind)
				}
			}
			prev = st
		}
	}
}
