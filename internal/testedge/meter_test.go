package testedge

import (
	"slices"
	"testing"
	"time"
)

func TestWire(t *testing.T) {
	a := Sample{Sent: 100, Recv: 50, SegsIn: 3, SegsOut: 4}
	b := Sample{Sent: 160, Recv: 90, SegsIn: 5, SegsOut: 5}
	if got, want := Wire(a, b), int64(60+40+3*TCPHeader); got != want {
		t.Fatalf("Wire %d, want %d", got, want)
	}
}

func TestBurstKind(t *testing.T) {
	for _, c := range []struct {
		kinds []string
		want  string
	}{
		{nil, "transport"},
		{[]string{"routeset_ack"}, "transport"},
		{[]string{"hello", "call:SIGNED_TIME", "ping"}, "start"},
		{[]string{"ping"}, "ping"},
		{[]string{"ping", "ping"}, "ping"},
		{[]string{"call:LIST_APPS"}, "call:LIST_APPS"},
		{[]string{"call:LIST_APPS", "other"}, "call:LIST_APPS"},
		{[]string{"call:LIST_APPS", "ping"}, "mixed"},
		{[]string{"call:LIST_APPS", "call:REPORT_HEALTH"}, "mixed"},
		{[]string{"call:"}, "transport"},
	} {
		if got := (Burst{Kinds: c.kinds}).Kind(); got != c.want {
			t.Errorf("%v: %s, want %s", c.kinds, got, c.want)
		}
	}
}

func TestBursts(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	s := func(ms int, sent, recv, in, out uint64) Sample {
		return Sample{At: at(ms), Sent: sent, Recv: recv, SegsIn: in, SegsOut: out}
	}
	samples := []Sample{
		s(0, 0, 0, 2, 1),
		s(1000, 100, 50, 3, 2),     // burst 1
		s(1050, 120, 50, 4, 2),     // burst 1, inside the gap
		s(5000, 120, 90, 5, 3),     // burst 2
		s(9000, 200, 90, 6, 4),     // burst 3, after to
		s(9500, 210, 100, 7, 5),    // after to
		s(20000, 300, 200, 10, 10), // after to
	}
	marks := []Mark{{At: at(995), Kind: "ping"}, {At: at(5005), Kind: "call:LIST_APPS"}, {At: at(3000), Kind: "hello"}}
	got := Bursts(samples, marks, t0, at(8000), 300*time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("%d bursts: %+v", len(got), got)
	}
	if b := got[0]; b.Bytes != 170+3*TCPHeader || b.Segments != 3 || !b.Start.Equal(at(990)) || !b.End.Equal(at(1050)) ||
		!slices.Equal(b.Kinds, []string{"ping"}) {
		t.Fatalf("burst 1 %+v", b)
	}
	if b := got[1]; b.Bytes != 40+2*TCPHeader || b.Segments != 2 || !slices.Equal(b.Kinds, []string{"call:LIST_APPS"}) {
		t.Fatalf("burst 2 %+v", b)
	}
	// A window that starts later counts from the last sample before it.
	late := Bursts(samples, marks, at(2000), at(8000), 300*time.Millisecond)
	if len(late) != 1 || late[0].Bytes != got[1].Bytes {
		t.Fatalf("late window %+v", late)
	}
	// A wider gap joins bursts.
	if wide := Bursts(samples, nil, t0, at(8000), 5*time.Second); len(wide) != 1 || wide[0].Bytes != got[0].Bytes+got[1].Bytes {
		t.Fatalf("wide gap %+v", wide)
	}
	if none := Bursts(samples[:1], nil, t0, at(8000), time.Second); len(none) != 0 {
		t.Fatalf("one sample gave %+v", none)
	}
}

func TestMedian(t *testing.T) {
	bs := []Burst{{Bytes: 5, Kinds: []string{"ping"}}, {Bytes: 1, Kinds: []string{"ping"}}, {Bytes: 9, Kinds: []string{"ping"}},
		{Bytes: 100, Kinds: []string{"call:LIST_APPS"}}}
	if m, n := Median(bs, "ping"); m != 5 || n != 3 {
		t.Fatalf("median %d of %d", m, n)
	}
	if m, n := Median(bs, "start"); m != 0 || n != 0 {
		t.Fatalf("median %d of %d", m, n)
	}
}

// A sample exactly one gap after a burst starts a new one, and only marks
// within half a gap of a burst belong to it.
func TestBurstEdges(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	samples := []Sample{{At: at(0)}, {At: at(1000), Sent: 10}, {At: at(1300), Sent: 20}}
	if got := Bursts(samples, nil, t0, at(5000), 300*time.Millisecond); len(got) != 2 {
		t.Fatalf("%d bursts, want 2: %+v", len(got), got)
	}
	// Burst [990, 1000]: half a gap is 150 ms either side.
	one := []Sample{{At: at(0)}, {At: at(1000), Sent: 10}}
	marks := []Mark{{At: at(830), Kind: "early"}, {At: at(845), Kind: "near-start"}, {At: at(1149), Kind: "near-end"}, {At: at(1160), Kind: "late"}}
	got := Bursts(one, marks, t0, at(5000), 300*time.Millisecond)
	if len(got) != 1 || !slices.Equal(got[0].Kinds, []string{"near-start", "near-end"}) {
		t.Fatalf("marks %+v", got)
	}
}

func TestMedianEven(t *testing.T) {
	var bs []Burst
	for _, b := range []int64{20, 1, 9, 5} {
		bs = append(bs, Burst{Bytes: b})
	}
	if m, n := Median(bs, "transport"); m != 9 || n != 4 {
		t.Fatalf("median %d of %d", m, n)
	}
}
