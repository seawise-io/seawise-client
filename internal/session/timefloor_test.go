package session

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

// fakeClocks drives the wall clock and the monotonic clock separately; a
// suspend moves the wall clock only.
type fakeClocks struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func (f *fakeClocks) Wall() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wall
}

func (f *fakeClocks) Mono() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mono
}

func (f *fakeClocks) run(d time.Duration) {
	f.mu.Lock()
	f.wall, f.mono = f.wall.Add(d), f.mono+d
	f.mu.Unlock()
}

func (f *fakeClocks) suspend(d time.Duration) {
	f.mu.Lock()
	f.wall = f.wall.Add(d)
	f.mu.Unlock()
}

func (f *fakeClocks) setWall(t time.Time) {
	f.mu.Lock()
	f.wall = t
	f.mu.Unlock()
}

func floorDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "v2")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTimeFloorPersistedAcrossRestart(t *testing.T) {
	dir := floorDir(t)
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if c.Ready() {
		t.Fatal("ready before any signed time")
	}
	c.Observe(1700000200)
	if !c.Ready() {
		t.Fatal("not ready after a signed time")
	}
	st, err := os.Lstat(filepath.Join(dir, TimeFloorFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal(st, err)
	}
	f2 := &fakeClocks{wall: time.Unix(1600000000, 0)}
	r := openSignedClock(dir, f2.Wall, f2.Mono, nil)
	if fl, ok := r.Floor(); !ok || fl != 1700000200 {
		t.Fatal(fl, ok)
	}
	if got := r.Now().Unix(); got != 1700000200 {
		t.Fatal("clock behind the persisted floor:", got)
	}
	if r.Ready() {
		t.Fatal("a persisted floor is not signed time for this run")
	}
	f2.setWall(time.Unix(1700009999, 0))
	if got := r.Now().Unix(); got != 1700009999 {
		t.Fatal("wall clock above the floor not used:", got)
	}
}

func TestTimeFloorBadFilesIgnored(t *testing.T) {
	for name, write := range map[string]func(p string) error{
		"corrupt": func(p string) error { return os.WriteFile(p, []byte("{"), 0o600) },
		"loose":   func(p string) error { return os.WriteFile(p, []byte(`{"schema":1,"floor":1900000000}`), 0o644) },
		"symlink": func(p string) error {
			o := p + ".real"
			if err := os.WriteFile(o, []byte(`{"schema":1,"floor":1900000000}`), 0o600); err != nil {
				return err
			}
			return os.Symlink(o, p)
		},
		"schema":   func(p string) error { return os.WriteFile(p, []byte(`{"schema":2,"floor":1900000000}`), 0o600) },
		"negative": func(p string) error { return os.WriteFile(p, []byte(`{"schema":1,"floor":-5}`), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := floorDir(t)
			if err := write(filepath.Join(dir, TimeFloorFile)); err != nil {
				t.Fatal(err)
			}
			f := &fakeClocks{wall: time.Unix(1700000000, 0)}
			c := openSignedClock(dir, f.Wall, f.Mono, nil)
			if _, ok := c.Floor(); ok || c.Now().Unix() != 1700000000 {
				t.Fatal("bad floor file used")
			}
			c.Observe(1700000100)
			if c.Now().Unix() != 1700000100 {
				t.Fatal(c.Now())
			}
		})
	}
}

func TestTimeFloorWritesAreThrottled(t *testing.T) {
	dir := floorDir(t)
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	read := func() int64 {
		b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
		var v struct{ Floor int64 }
		_ = json.Unmarshal(b, &v)
		return v.Floor
	}
	c.Observe(1700000000)
	c.Observe(1700000030)
	if read() != 1700000000 {
		t.Fatal(read())
	}
	c.Observe(1700000060)
	if read() != 1700000060 {
		t.Fatal(read())
	}
}

func TestSuspendMarksClockStale(t *testing.T) {
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	c := openSignedClock("", f.Wall, f.Mono, nil)
	c.Observe(1700000000)
	f.run(30 * time.Second)
	if !c.Ready() || c.Now().Unix() != 1700000030 {
		t.Fatal(c.Now())
	}
	select {
	case <-c.Wanted():
		t.Fatal("signed time wanted without a jump")
	default:
	}
	f.suspend(2 * time.Hour)
	if c.Ready() {
		t.Fatal("ready after the wall clock jumped")
	}
	select {
	case <-c.Wanted():
	default:
		t.Fatal("signed time not requested after a jump")
	}
	if got := c.Now().Unix(); got != 1700000030+7200 {
		t.Fatal("stale clock below the wall clock:", got)
	}
	c.Observe(1700007230)
	if !c.Ready() || c.Now().Unix() != 1700007230 {
		t.Fatal(c.Now())
	}
}

func TestWallStepBackStaleButNotBehind(t *testing.T) {
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	c := openSignedClock("", f.Wall, f.Mono, nil)
	c.Observe(1700000000)
	f.run(10 * time.Second)
	f.setWall(time.Unix(1600000000, 0))
	if c.Ready() || c.Now().Unix() != 1700000010 {
		t.Fatal(c.Ready(), c.Now().Unix())
	}
}

func TestRouteSetWithoutSignedTimeRequestsIt(t *testing.T) {
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	sc := openSignedClock("", f.Wall, f.Mono, nil)
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	r := h.dial()
	c := newConn(r.carriage, h.clock)
	r.reply <- dialRes{conn: c}
	c.in <- routeSetMsg(t, 1, testSessionID)
	c.expect(t, "SIGNED_TIME on stream 0", func(m *pb.ControlMessage) bool {
		return m.GetDeviceCall().GetMethod() == pb.DeviceMethod_SIGNED_TIME
	})
}

func TestStaleClockRequestsSignedTime(t *testing.T) {
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	sc := openSignedClock("", f.Wall, f.Mono, nil)
	sc.Observe(1700000000)
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	c := h.up(h.dial())
	f.suspend(time.Hour)
	_ = sc.Now()
	c.expect(t, "SIGNED_TIME after a jump", func(m *pb.ControlMessage) bool {
		return m.GetDeviceCall().GetMethod() == pb.DeviceMethod_SIGNED_TIME
	})
}

func TestClockJumpThreshold(t *testing.T) {
	for _, c := range []struct {
		jump  time.Duration
		stale bool
	}{{ClockJump, false}, {ClockJump + time.Second, true}, {-ClockJump, false}, {-ClockJump - time.Second, true}} {
		f := &fakeClocks{wall: time.Unix(1700000000, 0)}
		sc := openSignedClock("", f.Wall, f.Mono, nil)
		sc.Observe(1700000000)
		f.run(90 * time.Second)
		if !sc.Ready() {
			t.Fatal("stale without a jump")
		}
		f.suspend(c.jump)
		if sc.Ready() == c.stale {
			t.Errorf("jump %s: stale=%v", c.jump, !sc.Ready())
		}
	}
}

func TestFarFutureFloorHeals(t *testing.T) {
	dir := floorDir(t)
	if err := os.WriteFile(filepath.Join(dir, TimeFloorFile), []byte(`{"schema":1,"floor":1700036000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if c.Now().Unix() != 1700036000 {
		t.Fatal(c.Now())
	}
	c.Observe(1700000000)
	if fl, _ := c.Floor(); fl != 1700000000 || c.Now().Unix() != 1700000000 {
		t.Fatal("far-future floor kept:", fl, c.Now().Unix())
	}
	b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
	var v struct{ Floor int64 }
	_ = json.Unmarshal(b, &v)
	if v.Floor != 1700000000 {
		t.Fatal("floor file not rewritten:", string(b))
	}
}

func TestAcceptedSignedTimeBecomesTheFloor(t *testing.T) {
	dir := floorDir(t)
	if err := os.WriteFile(filepath.Join(dir, TimeFloorFile), []byte(`{"schema":1,"floor":1700003000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	c.Observe(1700000000)
	if fl, _ := c.Floor(); fl != 1700000000 {
		t.Fatal(fl)
	}
}

// shortCalls makes stream 0 calls give up quickly so heartbeats go over
// HTTPS, which the test server answers.
func shortCalls(t *testing.T) {
	old := callTimeout
	callTimeout = 20 * time.Millisecond
	t.Cleanup(func() { callTimeout = old })
}

func TestSignedTimeRetriedUntilSeen(t *testing.T) {
	shortCalls(t)
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	sc := openSignedClock("", f.Wall, f.Mono, nil)
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	var calls atomic.Int32
	h.hb.set(func(n string) (int, string) {
		if calls.Add(1) == 1 {
			return http.StatusServiceUnavailable, ""
		}
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700000100), "")
	})
	h.up(h.dial())
	<-h.hb.nonces
	h.settle()
	if sc.Ready() {
		t.Fatal("ready after a failed request")
	}
	h.advance(5 * time.Second)
	select {
	case <-h.hb.nonces:
	case <-time.After(5 * time.Second):
		t.Fatal("signed time not requested again")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !sc.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("clock not ready after the retry")
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.advance(10 * time.Minute)
	select {
	case n := <-h.hb.nonces:
		t.Fatal("still retrying once ready:", n)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSignedTimeBackoffDoubles(t *testing.T) {
	shortCalls(t)
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	sc := openSignedClock("", f.Wall, f.Mono, nil)
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	h.hb.set(func(string) (int, string) { return http.StatusServiceUnavailable, "" })
	h.up(h.dial())
	<-h.hb.nonces
	h.settle()
	for _, wait := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second} {
		h.advance(wait - time.Second)
		select {
		case <-h.hb.nonces:
			t.Fatalf("retry before %s", wait)
		case <-time.After(30 * time.Millisecond):
		}
		h.advance(time.Second)
		select {
		case <-h.hb.nonces:
		case <-time.After(5 * time.Second):
			t.Fatalf("no retry after %s", wait)
		}
		h.settle()
	}
}

func TestSignedTimeRequestWhileBusyRunsAfter(t *testing.T) {
	shortCalls(t)
	f := &fakeClocks{wall: time.Unix(1700000000, 0)}
	sc := openSignedClock("", f.Wall, f.Mono, nil)
	sc.Observe(1700000000)
	h := newHarness(t, func(c *Config) { c.SignedClock = sc })
	release := make(chan struct{})
	var calls atomic.Int32
	h.hb.set(func(n string) (int, string) {
		if calls.Add(1) == 1 {
			<-release
			return http.StatusServiceUnavailable, ""
		}
		return http.StatusOK, answerJSON(stateTok(t, n, "active", "active", 1700003700), "")
	})
	h.refuse(h.dial(), pb.RefuseCode_KEY_REVOKED)
	<-h.hb.nonces
	f.suspend(time.Hour)
	if sc.Ready() {
		t.Fatal("ready after a jump")
	}
	h.settle()
	close(release)
	select {
	case <-h.hb.nonces:
	case <-time.After(5 * time.Second):
		t.Fatal("request made while busy was lost")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !sc.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("clock not ready")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
