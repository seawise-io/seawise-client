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
		m := New(c.Initial.Generation, c.Initial.ModeOn)
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

var signedHolds = map[string]bool{HoldFlagsOff: true, HoldRevoked: true, HoldSuspended: true}

// Every case keeps the protections: only the four states and two
// transports; a HOLD that has no re-dial timer is entered only on a signed
// event (flags or signed state) or the local repair fact; a HOLD entered on
// an unsigned statement always carries a re-dial timer of at most 4 h.
func TestLadderProtections(t *testing.T) {
	for _, c := range loadLadder(t).Cases {
		prev := ""
		for i, s := range c.Steps {
			w := s.Want
			if w.State != Own && w.State != OwnWS && w.State != Reconnecting && w.State != Hold || w.Transport != TLS && w.Transport != WebSocket {
				t.Errorf("%s step %d: %s over %s", c.Name, i, w.State, w.Transport)
			}
			if (w.State == Hold) != (w.Hold != "") {
				t.Errorf("%s step %d: state %s with hold %q", c.Name, i, w.State, w.Hold)
			}
			if w.State == Hold && w.Hold != prev {
				signed := s.Event.Kind == EvFlags || s.Event.Kind == EvSignedState || (s.Event.Kind == EvStart && w.Hold == HoldFlagsOff)
				switch {
				case signedHolds[w.Hold] && !signed:
					t.Errorf("%s step %d: %s entered on %s", c.Name, i, w.Hold, s.Event.Kind)
				case w.Hold == HoldRepair && s.Event.Kind != EvRepair:
					t.Errorf("%s step %d: repair hold on %s", c.Name, i, s.Event.Kind)
				case !signedHolds[w.Hold] && w.Hold != HoldRepair:
					r, ok := w.Timers[TimerRedial]
					if !ok || r[1]-r[0] > ReprobeCap.Milliseconds() {
						t.Errorf("%s step %d: unsigned hold %s without a re-dial timer", c.Name, i, w.Hold)
					}
				}
			}
			prev = w.Hold
		}
	}
}
