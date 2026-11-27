package enrol

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seawise/client/internal/devicecall"
	"github.com/seawise/client/internal/identity"
	"github.com/seawise/client/internal/store"
)

func TestUpgradeEnrolsConfirmsAndClearsToken(t *testing.T) {
	v := newEnv(t)
	if Ready(v.st.State(), v.st.Secrets()) || !LegacyAllowed(v.st.State()) {
		t.Fatal("gates before enrolment")
	}
	if s := v.e.Status(); s.State != StateEnrolling {
		t.Fatalf("status %+v", s)
	}
	v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
	if !Ready(v.st.State(), v.st.Secrets()) || LegacyAllowed(v.st.State()) {
		t.Fatal("gates after enrolment")
	}
	if v.st.Secrets().FRPToken != testToken {
		t.Fatal("token cleared before the switch")
	}
	v.run(20, v.switched)
	v.intact()
	if v.fake.enrolCount() != 1 || v.fake.switchCount() != 1 || v.fake.live() {
		t.Fatalf("server: %d enrolments, %d switches", v.fake.enrolCount(), v.fake.switchCount())
	}
	k, err := v.ks.Current()
	if err != nil || k.KeyID() != v.fake.kid() || v.st.State().Enrolment.KeyID != k.KeyID() {
		t.Fatal("enrolled key is not the local key")
	}
	if v.changes != 2 {
		t.Fatalf("OnChange ran %d times", v.changes)
	}
	if s := v.e.Status(); s.State != StateSwitched || s.KeyFingerprint != k.Fingerprint() {
		t.Fatalf("status %+v", s)
	}
	fi, err := os.Stat(filepath.Join(v.st.Dir(), identity.KeyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("key file mode")
	}
	b, _ := os.ReadFile(filepath.Join(v.st.Dir(), store.SecretsFile))
	if strings.Contains(string(b), testToken) {
		t.Fatal("token still in secrets file")
	}
	if d := v.step(); d != idleCheck {
		t.Fatalf("done step waits %v", d)
	}
	v.reopen()
	if !v.switched() || v.step() != idleCheck {
		t.Fatal("switch not kept across restart")
	}
	if v.fake.count(PathEnroll) == 0 || v.fake.count(PathConfirm) != 1 || v.fake.count(PathIdentity) != 1 {
		t.Fatal("unexpected call counts")
	}
}

func TestTokenOnlyOnEnrol(t *testing.T) {
	v := newEnv(t)
	var mu sync.Mutex
	var paths []string
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FRP-Token") != "" {
			mu.Lock()
			paths = append(paths, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		v.fake.ServeHTTP(w, r)
	})
	v.run(30, v.switched)
	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if p != "POST "+PathEnroll {
			t.Fatalf("token sent on %s", p)
		}
	}
	if len(paths) == 0 {
		t.Fatal("token never sent")
	}
}

// A restart after any number of steps resumes and finishes with one
// enrolment and the same key.
func TestResumeAfterEveryStep(t *testing.T) {
	full := newEnv(t)
	n := 0
	for !full.switched() {
		full.step()
		n++
		if n > 30 {
			t.Fatal("does not finish")
		}
	}
	for k := 0; k <= n; k++ {
		v := newEnv(t)
		for i := 0; i < k; i++ {
			v.step()
		}
		v.reopen()
		v.run(30, v.switched)
		v.intact()
		if v.fake.enrolCount() != 1 || v.fake.switchCount() != 1 {
			t.Fatalf("restart after %d steps: %d enrolments, %d switches", k, v.fake.enrolCount(), v.fake.switchCount())
		}
		if cur, _ := v.ks.Current(); cur.KeyID() != v.fake.kid() {
			t.Fatalf("restart after %d steps: key changed", k)
		}
	}
}

// A key written before its record survives a crash and is reused.
func TestCrashBetweenKeyAndRecord(t *testing.T) {
	v := newEnv(t)
	v.step() // pending record
	k, err := v.ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	kid := k.KeyID()
	v.reopen()
	v.run(30, v.switched)
	if v.fake.kid() != kid {
		t.Fatal("existing key not reused")
	}
}

func TestLostAnswersResume(t *testing.T) {
	for _, path := range []string{PathEnroll, PathIdentity, PathConfirm} {
		t.Run(path, func(t *testing.T) {
			v := newEnv(t)
			v.fake.with(func(f *fakeC12) { f.lose[path] = 1 })
			v.run(30, v.switched)
			v.intact()
			if v.fake.enrolCount() != 1 || v.fake.switchCount() != 1 {
				t.Fatalf("%d enrolments, %d switches", v.fake.enrolCount(), v.fake.switchCount())
			}
			if !strings.Contains(v.logs.String(), "retrying") {
				t.Fatal("lost answer not retried")
			}
		})
	}
}

func TestLostAnswerThenRestart(t *testing.T) {
	v := newEnv(t)
	v.fake.with(func(f *fakeC12) { f.lose[PathConfirm] = 1 })
	v.run(30, func() bool { return v.fake.switchCount() == 1 })
	if v.st.Secrets().FRPToken != testToken || v.phase() != store.PhaseEnrolled {
		t.Fatal("state moved without an answer")
	}
	v.reopen()
	v.run(30, v.switched)
	if v.fake.switchCount() != 1 {
		t.Fatal("switched twice")
	}
}

func TestServerErrorsKeepStateAndBackOff(t *testing.T) {
	v := newEnv(t)
	v.fake.with(func(f *fakeC12) {
		f.script[PathEnroll] = []int{503, 500, 404, 502}
	})
	v.step() // record
	v.step() // key
	var last time.Duration
	for i := 0; i < 4; i++ {
		d := v.step()
		if d <= last || d > backoffMax {
			t.Fatalf("attempt %d: delay %v after %v", i, d, last)
		}
		last = d
		if v.phase() != store.PhasePending || v.holdReason() != "" || v.st.Secrets().FRPToken != testToken {
			t.Fatal("state changed on a server error")
		}
		v.intact()
		if s := v.e.Status(); s.LastError == "" || s.NextAttempt.IsZero() || s.State != StateEnrolling {
			t.Fatalf("status %+v", s)
		}
	}
	v.run(30, v.switched)
	if s := v.e.Status(); s.LastError != "" {
		t.Fatalf("error kept after success: %+v", s)
	}
}

func TestBackoffCaps(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	v.fake.with(func(f *fakeC12) {
		for range 20 {
			f.script[PathEnroll] = append(f.script[PathEnroll], 503)
		}
	})
	var d time.Duration
	for i := 0; i < 15; i++ {
		d = v.step()
	}
	if d != backoffMax {
		t.Fatalf("delay %v", d)
	}
}

func TestRateLimitHonoursRetryAfter(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	v.fake.with(func(f *fakeC12) { f.script[PathEnroll] = []int{429}; f.retryAfter = "900" })
	if d := v.step(); d != 900*time.Second {
		t.Fatalf("delay %v", d)
	}
	v.fake.with(func(f *fakeC12) { f.script[PathEnroll] = []int{429}; f.retryAfter = "99999" })
	if d := v.step(); d != time.Hour {
		t.Fatalf("delay %v, want the 1 h cap", d)
	}
	v.run(30, v.switched)
}

func TestNonceChallengeRetriedOnce(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	v.step()
	if v.phase() != store.PhaseEnrolled {
		t.Fatalf("phase %s", v.phase())
	}
	if n := v.fake.count(PathEnroll); n != 2 {
		t.Fatalf("%d enrol calls, want the challenge and the call", n)
	}
}

func TestReplayedProofRetried(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	fixed := "fixed-jti-fixed-jti-fixed"
	v.jti.Store(&fixed)
	v.fake.with(func(f *fakeC12) {
		k, _ := v.ks.Current()
		f.seen[k.KeyID()+":fixed-jti-fixed-jti-fixed"] = true
	})
	v.step()
	if v.phase() != store.PhasePending || v.holdReason() != "" || !strings.Contains(v.e.Status().LastError, "replayed") {
		t.Fatalf("status %+v", v.e.Status())
	}
	v.jti.Store(nil)
	v.run(30, v.switched)
}

func TestRefusalsHold(t *testing.T) {
	cases := []struct {
		name  string
		setup func(v *env)
		hold  string
	}{
		{"repair", func(v *env) { v.fake.with(func(f *fakeC12) { f.repair = true }) }, store.HoldRepairRequired},
		{"token", func(v *env) { v.fake.with(func(f *fakeC12) { f.tokenHash = strings.Repeat("0", 64) }) }, store.HoldInvalidToken},
		{"clone", func(v *env) { v.fake.with(func(f *fakeC12) { f.deviceKID, f.deviceStatus = "another-key", "active" }) }, store.HoldAlreadyEnrolled},
		{"bad key", func(v *env) {
			v.step()
			k, _ := v.ks.Create()
			v.fake.with(func(f *fakeC12) { f.registered[k.KeyID()] = true })
		}, store.HoldBadKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t)
			c.setup(v)
			var d time.Duration
			for i := 0; i < 10 && v.holdReason() == ""; i++ {
				d = v.step()
			}
			if v.holdReason() != c.hold || d != holdRetry {
				t.Fatalf("hold %q after %v", v.holdReason(), d)
			}
			v.intact()
			if v.st.Secrets().FRPToken != testToken || v.phase() != store.PhasePending {
				t.Fatal("refusal changed the token or phase")
			}
			s := v.e.Status()
			if s.State != StateHeld || s.Hold != c.hold || s.HoldText == "" {
				t.Fatalf("status %+v", s)
			}
			if Ready(v.st.State(), v.st.Secrets()) {
				t.Fatal("tunnel allowed with an unenrolled key")
			}
			calls := v.fake.count(PathEnroll)
			if d := v.step(); d <= 0 || d > holdRetry || v.fake.count(PathEnroll) != calls {
				t.Fatal("hold retried early")
			}
			v.clk.add(holdRetry)
			v.step()
			if v.fake.count(PathEnroll) == calls {
				t.Fatal("hold not retried after its interval")
			}
			calls = v.fake.count(PathEnroll)
			v.reopen()
			v.step()
			if v.fake.count(PathEnroll) == calls {
				t.Fatal("hold not retried after a restart")
			}
			if v.holdReason() != c.hold {
				t.Fatal("hold lost")
			}
		})
	}
}

func TestHoldClearsOnSuccess(t *testing.T) {
	v := newEnv(t)
	v.fake.with(func(f *fakeC12) { f.repair = true })
	v.run(10, func() bool { return v.holdReason() != "" })
	v.fake.with(func(f *fakeC12) { f.repair = false })
	v.clk.add(holdRetry)
	v.run(30, v.switched)
	if v.holdReason() != "" {
		t.Fatal("hold kept")
	}
}

func TestSwitchRefusalsHold(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *fakeC12)
		hold  string
	}{
		{"revoked", func(f *fakeC12) { f.deviceStatus = "revoked" }, store.HoldKeyRevoked},
		{"not enrolled", func(f *fakeC12) { f.fromToken = false }, store.HoldNotEnrolled},
		{"other server", func(f *fakeC12) { f.serverID = "7a6b5c4d-3e2f-4a1b-8c9d-0e1f2a3b4c5d" }, store.HoldIdentity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newEnv(t)
			v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
			k, _ := v.ks.Current()
			v.fake.with(c.setup)
			v.run(10, func() bool { return v.holdReason() != "" })
			if v.holdReason() != c.hold {
				t.Fatalf("hold %q", v.holdReason())
			}
			v.intact()
			if cur, _ := v.ks.Current(); cur.KeyID() != k.KeyID() || v.st.Secrets().FRPToken != testToken || v.phase() != store.PhaseEnrolled {
				t.Fatal("refusal changed key, token or phase")
			}
			if v.fake.enrolCount() != 1 {
				t.Fatal("enrolled again after a refusal")
			}
		})
	}
}

func TestConfirmWrongServerHolds(t *testing.T) {
	v := newEnv(t)
	v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
	v.step() // probe
	v.fake.with(func(f *fakeC12) { f.serverID = "7a6b5c4d-3e2f-4a1b-8c9d-0e1f2a3b4c5d" })
	v.step()
	if v.holdReason() != store.HoldSwitchRefused {
		t.Fatalf("hold %q", v.holdReason())
	}
}

func TestUnknownKeyEnrolsAgain(t *testing.T) {
	v := newEnv(t)
	v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
	k, _ := v.ks.Current()
	v.fake.with(func(f *fakeC12) { f.deviceKID, f.deviceStatus = "", ""; delete(f.registered, k.KeyID()) })
	v.step()
	if v.phase() != store.PhasePending || v.holdReason() != "" {
		t.Fatalf("phase %s hold %s", v.phase(), v.holdReason())
	}
	v.run(30, v.switched)
	if cur, _ := v.ks.Current(); cur.KeyID() != k.KeyID() {
		t.Fatal("new key made")
	}
}

func TestKeyLostHolds(t *testing.T) {
	v := newEnv(t)
	v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
	if err := os.Remove(filepath.Join(v.st.Dir(), identity.KeyFile)); err != nil {
		t.Fatal(err)
	}
	v.reopen()
	v.step()
	if v.holdReason() != store.HoldKeyLost {
		t.Fatalf("hold %q", v.holdReason())
	}
	if _, err := v.ks.Current(); err == nil {
		t.Fatal("new key made for an enrolled server")
	}
	v.intact()
}

func TestLocalHolds(t *testing.T) {
	t.Run("insecure origin", func(t *testing.T) {
		v := newEnv(t)
		v.origin = "http://" + strings.TrimPrefix(v.srv.URL, "https://")
		v.run(5, func() bool { return v.holdReason() != "" })
		if v.holdReason() != store.HoldInsecureOrigin || v.fake.count(PathEnroll) != 0 {
			t.Fatal("token sent over plain http")
		}
	})
	t.Run("token format", func(t *testing.T) {
		v := newEnvToken(t, strings.ToUpper(testToken))
		v.run(5, func() bool { return v.holdReason() != "" })
		if v.holdReason() != store.HoldTokenUnusable || v.fake.count(PathEnroll) != 0 {
			t.Fatal("malformed token sent")
		}
	})
}

func TestInsecureClientRefused(t *testing.T) {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- the refusal is under test
	v := newEnv(t)
	if _, err := New(Config{Store: v.st, Keys: v.ks, Origin: func() string { return v.origin }, Client: c}); !errors.Is(err, devicecall.ErrInsecureTLS) {
		t.Fatal("insecure client accepted")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Store(true) }))
	defer other.Close()
	v := newEnv(t)
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	v.step()
	v.step()
	v.step()
	if leaked.Load() || v.phase() != store.PhasePending || v.e.Status().LastError == "" {
		t.Fatal("redirect followed or accepted")
	}
}

func TestUntrustedCertificateFails(t *testing.T) {
	v := newEnv(t)
	v.client = &http.Client{}
	v.reopen()
	v.step()
	v.step()
	v.step()
	if v.fake.count(PathEnroll) != 0 || !strings.Contains(v.e.Status().LastError, "unreachable") {
		t.Fatalf("status %+v", v.e.Status())
	}
}

func TestUnexpectedSuccessAnswers(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":"enrolled","server_id":"` + testServer + `","device_id":"x","key_id":"y"}`))
	})
	v.step()
	if v.phase() != store.PhasePending || v.holdReason() != "" {
		t.Fatal("malformed answer accepted")
	}
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		k, _ := v.ks.Current()
		_, _ = w.Write([]byte(`{"result":"enrolled","server_id":"7a6b5c4d-3e2f-4a1b-8c9d-0e1f2a3b4c5d","device_id":"d0000000-0000-4000-8000-000000000001","key_id":"` + k.KeyID() + `"}`))
	})
	v.step()
	if v.holdReason() != store.HoldIdentity {
		t.Fatalf("hold %q", v.holdReason())
	}
}

func TestNotNeeded(t *testing.T) {
	st, err := store.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ks, err := identity.OpenFile(st.Dir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	e, err := New(Config{Store: st, Keys: ks, Origin: func() string { return "https://api.seawise.io" }})
	if err != nil {
		t.Fatal(err)
	}
	if d := e.Step(t.Context()); d != idleCheck || e.Status().State != StateNotNeeded {
		t.Fatalf("%v %+v", d, e.Status())
	}
	if _, err := ks.Current(); err == nil {
		t.Fatal("key made without an account")
	}
	if !Ready(st.State(), st.Secrets()) || !LegacyAllowed(st.State()) {
		t.Fatal("gates without an account")
	}
	if _, err := New(Config{Store: st}); err == nil {
		t.Fatal("config without keys accepted")
	}
}

func TestClearAfterCrashBetweenSwitchAndClear(t *testing.T) {
	v := newEnv(t)
	v.run(30, func() bool { return v.phase() == store.PhaseSwitched })
	if v.st.Secrets().FRPToken == "" {
		t.Fatal("token cleared in the same step as the switch")
	}
	v.reopen()
	v.step()
	if !v.switched() {
		t.Fatal("token not cleared after restart")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	v := newEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	done := make(chan error, 1)
	go func() { done <- v.e.Run(ctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && v.e.Status().State != StateSwitched {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("Run returned nil")
	}
	if v.e.Status().State != StateSwitched {
		t.Fatalf("status %+v", v.e.Status())
	}
}

func TestBackoffDelays(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	v.e.cfg.Jitter = func() float64 { return 1.2 }
	v.fake.with(func(f *fakeC12) { f.script[PathEnroll] = []int{503, 503, 503} })
	for i, want := range []time.Duration{36 * time.Second, 72 * time.Second, 144 * time.Second} {
		if d := v.step(); d != want {
			t.Fatalf("attempt %d: %v, want %v", i, d, want)
		}
	}
}

func TestReplacedKeyHolds(t *testing.T) {
	v := newEnv(t)
	v.run(20, func() bool { return v.phase() == store.PhaseEnrolled })
	if err := os.Remove(filepath.Join(v.st.Dir(), identity.KeyFile)); err != nil {
		t.Fatal(err)
	}
	v.reopen()
	other, err := v.ks.Create()
	if err != nil {
		t.Fatal(err)
	}
	v.step()
	if v.holdReason() != store.HoldKeyLost || v.fake.count(PathConfirm) != 0 || v.fake.count(PathIdentity) != 0 {
		t.Fatalf("replaced key used: hold %q", v.holdReason())
	}
	if cur, _ := v.ks.Current(); cur.KeyID() != other.KeyID() {
		t.Fatal("key changed")
	}
}

func TestNonceChallengeRetriedOnlyOnce(t *testing.T) {
	v := newEnv(t)
	v.step()
	v.step()
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "n1.fresh")
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","code":"use_dpop_nonce"}`))
	})
	var n atomic.Int32
	inner := v.handler.Load().h
	v.serve(func(w http.ResponseWriter, r *http.Request) { n.Add(1); inner.ServeHTTP(w, r) })
	v.step()
	if n.Load() != 2 || v.phase() != store.PhasePending {
		t.Fatalf("%d calls", n.Load())
	}
}

func TestAnswerSizeCap(t *testing.T) {
	for _, size := range []int{devicecall.MaxAnswer, devicecall.MaxAnswer + 1} {
		v := newEnv(t)
		v.step()
		v.step()
		v.serve(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(strings.Repeat(" ", size)))
		})
		v.step()
		tooLarge := strings.Contains(v.e.Status().LastError, "too large")
		if tooLarge != (size > devicecall.MaxAnswer) {
			t.Fatalf("size %d: %q", size, v.e.Status().LastError)
		}
	}
}

func TestContentTypeOnlyWithBody(t *testing.T) {
	v := newEnv(t)
	var mu sync.Mutex
	got := map[string]string{}
	v.serve(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.Method+" "+r.URL.Path] = r.Header.Get("Content-Type")
		mu.Unlock()
		v.fake.ServeHTTP(w, r)
	})
	v.run(30, v.switched)
	mu.Lock()
	defer mu.Unlock()
	if got["POST "+PathEnroll] != "application/json" || got["POST "+PathConfirm] != "application/json" || got["GET "+PathIdentity] != "" {
		t.Fatalf("content types %v", got)
	}
}

func TestLegacyStopsOnRefusedToken(t *testing.T) {
	v := newEnv(t)
	v.fake.with(func(f *fakeC12) { f.tokenHash = strings.Repeat("0", 64) })
	v.run(10, func() bool { return v.holdReason() != "" })
	if LegacyAllowed(v.st.State()) {
		t.Fatal("1.x calls allowed with a refused token")
	}
	if v.st.Secrets().FRPToken != testToken {
		t.Fatal("token removed")
	}
}

// A key the server enrols but then does not know is enrolled again at most
// three times, with growing delays, then held.
func TestUnknownKeyLoopHolds(t *testing.T) {
	v := newEnv(t)
	forget := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathIdentity {
			v.fake.with(func(f *fakeC12) { f.deviceKID, f.deviceStatus = "", ""; f.registered = map[string]bool{} })
		}
		v.fake.ServeHTTP(w, r)
	}
	v.serve(forget)
	var delays []time.Duration
	for i := 0; i < 40 && v.holdReason() == ""; i++ {
		if d := v.step(); d > 0 {
			delays = append(delays, d)
		}
	}
	if v.holdReason() != store.HoldKeyUnknown {
		t.Fatalf("hold %q", v.holdReason())
	}
	if n := v.fake.enrolCount(); n != 3 {
		t.Fatalf("%d enrolments", n)
	}
	for i := 1; i < len(delays)-1; i++ {
		if delays[i] <= delays[i-1] {
			t.Fatalf("delays reset: %v", delays)
		}
	}
	v.intact()
	if v.st.Secrets().FRPToken != testToken {
		t.Fatal("token removed")
	}
}

func TestFutureHoldTimeIsCapped(t *testing.T) {
	v := newEnv(t)
	v.step()
	future := v.clk.now().Add(365 * 24 * time.Hour)
	if err := v.st.Update(func(st *store.State) error {
		st.Enrolment.Hold, st.Enrolment.HoldAt = store.HoldRepairRequired, &future
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if d := v.step(); d != holdRetry {
		t.Fatalf("wait %v", d)
	}
}

func TestSwitchedWithoutKeyShowsKeyLost(t *testing.T) {
	v := newEnv(t)
	v.run(30, v.switched)
	if err := os.Remove(filepath.Join(v.st.Dir(), identity.KeyFile)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(v.st.Dir(), store.StateFile))
	v.reopen()
	v.step()
	if s := v.e.Status(); s.State != StateHeld || s.Hold != store.HoldKeyLost || s.HoldText == "" {
		t.Fatalf("status %+v", s)
	}
	after, _ := os.ReadFile(filepath.Join(v.st.Dir(), store.StateFile))
	if string(before) != string(after) || v.holdReason() != "" {
		t.Fatal("state changed")
	}
	if _, err := v.ks.Current(); err == nil {
		t.Fatal("key made")
	}
	if _, err := v.ks.Create(); err != nil {
		t.Fatal(err)
	}
	v.step()
	if s := v.e.Status(); s.Hold != store.HoldKeyLost {
		t.Fatalf("replaced key not shown: %+v", s)
	}
}

func TestKeystoreErrorIsNotKeyLost(t *testing.T) {
	v := newEnv(t)
	v.run(30, v.switched)
	v.ks.Close()
	v.step()
	s := v.e.Status()
	if s.State != StateSwitched || s.Hold != "" || !strings.Contains(s.LastError, identity.ErrClosed.Error()) || s.KeyFingerprint != "" {
		t.Fatalf("status %+v", s)
	}
	v.ks = nil
}

func TestKeystoreErrorKeepsEarlierError(t *testing.T) {
	v := newEnv(t)
	v.ks.Close()
	v.e.setStatus("store: disk full", time.Time{})
	if s := v.e.Status(); s.LastError != "store: disk full" {
		t.Fatalf("status %+v", s)
	}
	v.ks = nil
}

func TestKeyedAccountSendsNoLegacyCalls(t *testing.T) {
	st := store.State{Account: &store.Account{ServerID: testServer, DeviceID: "d0000000-0000-4000-8000-000000000001", KeyID: strings.Repeat("A", 43)}}
	if LegacyAllowed(st) || !Ready(st, store.Secrets{}) {
		t.Fatal("an account paired with its device key must not send 1.x calls")
	}
	if !LegacyAllowed(store.State{Account: &store.Account{ServerID: testServer}}) {
		t.Fatal("an imported account sends 1.x calls until enrolled")
	}
}

// No pairing path exists for a paired or held server, so no hold asks for
// one; each points at the server's page instead.
func TestHoldTextsNeedNoLocalPairing(t *testing.T) {
	for reason, text := range holdText {
		if strings.Contains(strings.ToLower(text), "pair") {
			t.Errorf("%s: %q asks for pairing", reason, text)
		}
	}
	for _, r := range []string{store.HoldInvalidToken, store.HoldAlreadyEnrolled, store.HoldBadKey, store.HoldRepairRequired, store.HoldKeyRevoked, store.HoldTokenUnusable, store.HoldServerID, store.HoldKeyLost, store.HoldKeyUnknown} {
		if !strings.HasSuffix(holdText[r], reconnectText) {
			t.Errorf("%s: %q", r, holdText[r])
		}
	}
}

func TestNeedsReconnect(t *testing.T) {
	for hold, text := range holdText {
		if NeedsReconnect(hold) != strings.HasSuffix(text, reconnectText) {
			t.Errorf("%s", hold)
		}
	}
	for _, h := range []string{store.HoldKeyLost, store.HoldRepairRequired, store.HoldKeyRevoked, store.HoldInvalidToken} {
		if !NeedsReconnect(h) {
			t.Errorf("%s needs a new pairing", h)
		}
	}
	for _, h := range []string{"", store.HoldInvalidRequest, store.HoldInsecureOrigin, "unknown"} {
		if NeedsReconnect(h) {
			t.Errorf("%q does not", h)
		}
	}
}
