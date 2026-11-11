//go:build flakynet

package flakynet

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seawise/client/internal/testedge"
)

// Recovery limits: reconnects must finish within 60 s (p95). Raw TLS
// blocked mid-session first needs the liveness timeout (35 s) and two
// refused raw TLS dials before the WebSocket carriage.
const (
	recoverWithin   = 60 * time.Second
	carriageWithin  = 90 * time.Second
	steadyLostGrace = 60 * time.Second
)

// scenario is one line of scenarios.jsonl, written by run.sh: the fault
// is applied at Start and removed at End.
type scenario struct {
	Name  string    `json:"name"`
	Kind  string    `json:"kind"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func readLines[T any](t *testing.T, path string) []T {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, v)
	}
	return out
}

// TestFlakyReport checks every scenario of a run against the edge's
// event log.
func TestFlakyReport(t *testing.T) {
	dir := os.Getenv("FLAKYNET_DIR")
	if os.Getenv("FLAKYNET_ROLE") != "report" || dir == "" {
		t.Skip("run by run.sh")
	}
	events := readLines[testedge.Event](t, filepath.Join(dir, "events.jsonl"))
	scenarios := readLines[scenario](t, filepath.Join(dir, "scenarios.jsonl"))
	bursts := readLines[burstLine](t, filepath.Join(dir, "bursts.jsonl"))
	if len(scenarios) == 0 {
		t.Fatal("no scenarios ran")
	}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			check(t, s, events)
			var bytes int64
			for _, b := range bursts {
				if !b.Start.Before(s.Start) && b.Start.Before(s.End) {
					bytes += b.Bytes
				}
			}
			t.Logf("%s: %d B on the tunnel in %v", s.Name, bytes, s.End.Sub(s.Start).Round(time.Second))
		})
	}
}

func check(t *testing.T, s scenario, events []testedge.Event) {
	upBefore := map[int64]bool{}
	for _, e := range events {
		if e.At.After(s.Start) {
			break
		}
		switch e.Kind {
		case "up":
			upBefore[e.Conn] = true
		case "down":
			delete(upBefore, e.Conn)
		}
	}
	firstUp := func(after time.Time, carriage string) (time.Time, bool) {
		for _, e := range events {
			if e.Kind == "up" && e.At.After(after) && (carriage == "" || e.Carriage == carriage) {
				return e.At, true
			}
		}
		return time.Time{}, false
	}
	// pingAfter is the first ping after t on a session that was up before
	// the fault: the session survived it.
	pingAfter := func(after time.Time) (time.Time, bool) {
		for _, e := range events {
			if e.Kind == "ping" && e.At.After(after) && upBefore[e.Conn] {
				return e.At, true
			}
		}
		return time.Time{}, false
	}
	switch s.Kind {
	case "steady":
		lost := 0
		for _, e := range events {
			if e.Kind == "down" && upBefore[e.Conn] && e.At.After(s.Start) && e.At.Before(s.End) {
				lost++
				up, ok := firstUp(e.At, "")
				if !ok || up.Sub(e.At) > steadyLostGrace {
					t.Errorf("session lost at %v and not back within %v", e.At.Sub(s.Start).Round(time.Second), steadyLostGrace)
				}
			}
		}
		pings := 0
		for _, e := range events {
			if e.Kind == "ping" && e.At.After(s.Start) && e.At.Before(s.End) {
				pings++
			}
		}
		if pings == 0 {
			t.Error("no ping answered during the scenario")
		}
		t.Logf("%s: sessions lost %d, pings answered %d", s.Name, lost, pings)
	case "outage":
		var r time.Time
		up, okUp := firstUp(s.Start, "")
		ping, okPing := pingAfter(s.End)
		switch {
		case okUp && (!okPing || up.Before(ping)):
			r = up
		case okPing:
			r = ping
		default:
			t.Fatal("no session after the fault")
		}
		rec := max(r.Sub(s.End), 0)
		t.Logf("%s: recovered %v after the fault ended (survived: %v)", s.Name, rec.Round(100*time.Millisecond), !(okUp && (!okPing || up.Before(ping))))
		if rec > recoverWithin {
			t.Errorf("recovery %v over %v", rec, recoverWithin)
		}
	case "raw_block":
		up, ok := firstUp(s.Start, "websocket")
		if !ok {
			t.Fatal("no WebSocket session after raw TLS was blocked")
		}
		rec := up.Sub(s.Start)
		t.Logf("%s: on WebSocket %v after raw TLS was blocked", s.Name, rec.Round(100*time.Millisecond))
		if rec > carriageWithin {
			t.Errorf("WebSocket after %v, over %v", rec, carriageWithin)
		}
		var conn int64
		for _, e := range events {
			if e.Kind == "up" && e.At.Equal(up) {
				conn = e.Conn
			}
		}
		stayed := false
		for _, e := range events {
			if e.Kind == "ping" && e.Conn == conn && e.At.After(up.Add(30*time.Second)) && e.At.Before(s.End) {
				stayed = true
			}
		}
		if !stayed {
			t.Error("the WebSocket session did not stay up")
		}
	case "clock":
		up, ok := firstUp(s.Start, "")
		if !ok {
			t.Fatal("no session with the clock offset")
		}
		rec := up.Sub(s.Start)
		t.Logf("%s: session %v after the agent started", s.Name, rec.Round(100*time.Millisecond))
		if rec > recoverWithin {
			t.Errorf("session after %v, over %v", rec, recoverWithin)
		}
		answered := false
		for _, e := range events {
			if e.Kind == "call" && e.At.After(up) && e.At.Before(s.End) {
				if strings.HasSuffix(e.Detail, " 200") {
					answered = true
				} else {
					t.Errorf("device call refused: %s", e.Detail)
				}
			}
		}
		if !answered {
			t.Error("no device call answered on the session")
		}
	default:
		t.Fatalf("unknown scenario kind %q", s.Kind)
	}
}
