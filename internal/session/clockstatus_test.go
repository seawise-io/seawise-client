package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sane is a plausible system clock for this build.
var sane = MinPlausible.Add(30 * 24 * time.Hour)

func writeFloor(t *testing.T, dir string, floor int64) { writeFloorAs(t, dir, floor, false) }

func writeFloors(t *testing.T, dir string, floor, corroborated int64) {
	t.Helper()
	b, _ := json.Marshal(floorFile{Schema: 1, Floor: floor, Corroborated: corroborated})
	if err := os.WriteFile(filepath.Join(dir, TimeFloorFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFloorAs(t *testing.T, dir string, floor int64, corroborated bool) {
	t.Helper()
	f := floorFile{Schema: 1, Floor: floor}
	if corroborated {
		f.Corroborated = floor
	}
	b, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, TimeFloorFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFloor(t *testing.T, dir string) int64 {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
	var f floorFile
	_ = json.Unmarshal(b, &f)
	return f.Floor
}

// The status shows how far off the system clock is from signed time.
func TestClockStatus(t *testing.T) {
	lim := clockWrongSec
	for _, tc := range []struct {
		name  string
		skew  int64
		state string
	}{
		{"exact", 0, ClockSigned},
		{"ahead at limit", lim, ClockSigned},
		{"behind at limit", -lim, ClockSigned},
		{"ahead past limit", lim + 1, ClockIsWrong},
		{"behind past limit", -lim - 1, ClockIsWrong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeClocks{wall: sane.Add(time.Duration(tc.skew) * time.Second)}
			c := openSignedClock("", f.Wall, f.Mono, nil)
			c.Observe(sane.Unix())
			f.run(30 * time.Second)
			s := c.Status()
			if s.State != tc.state || s.Offset == nil || *s.Offset != tc.skew {
				t.Fatalf("%+v offset %v", s, s.Offset)
			}
			if trusted := tc.state == ClockSigned; (s.Floor == sane.Unix()) != trusted {
				t.Fatalf("floor %d, trusted %v", s.Floor, trusted)
			}
			if (s.Text == clockWrongText) != (tc.state == ClockIsWrong) {
				t.Fatalf("text %q for %s", s.Text, s.State)
			}
		})
	}
}

func TestClockStatusWaitingWithoutRTC(t *testing.T) {
	f := &fakeClocks{wall: time.Unix(0, 0)}
	c := openSignedClock("", f.Wall, f.Mono, nil)
	if s := c.Status(); s.State != ClockUnsigned || s.Text != clockWaitingText {
		t.Fatalf("%+v", s)
	}
}

func TestClockStatusBeforeSignedTime(t *testing.T) {
	dir := floorDir(t)
	f := &fakeClocks{wall: sane}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if s := c.Status(); s.State != ClockUnsigned || s.Offset != nil || s.Floor != 0 || s.Text != "" {
		t.Fatalf("%+v", s)
	}
	c.Observe(sane.Unix())

	for _, tc := range []struct {
		name  string
		wall  time.Time
		state string
	}{
		{"wall ahead of floor", sane.Add(time.Hour), ClockUnsigned},
		{"wall behind floor within limit", sane.Add(-ClockWrong), ClockUnsigned},
		{"wall behind floor past limit", sane.Add(-ClockWrong - time.Second), ClockIsWrong},
		{"no real-time clock", time.Unix(0, 0), ClockIsWrong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeClocks{wall: tc.wall}
			r := openSignedClock(dir, g.Wall, g.Mono, nil)
			s := r.Status()
			if s.State != tc.state || s.Offset != nil || s.Floor != sane.Unix() {
				t.Fatalf("%+v", s)
			}
			if (s.Text == clockBehindText) != (tc.state == ClockIsWrong) {
				t.Fatalf("text %q for %s", s.Text, s.State)
			}
		})
	}
}

func TestClockStatusAfterJump(t *testing.T) {
	f := &fakeClocks{wall: sane}
	c := openSignedClock("", f.Wall, f.Mono, nil)
	c.Observe(sane.Unix())
	f.suspend(2 * ClockJump)
	if s := c.Status(); s.State != ClockUnsigned || s.Offset != nil {
		t.Fatalf("a jumped clock is not corrected: %+v", s)
	}
	select {
	case <-c.Wanted():
	default:
		t.Fatal("status did not ask for signed time after a jump")
	}
	f.setWall(sane.Add(-24 * time.Hour))
	if s := c.Status(); s.State != ClockIsWrong || s.Text != clockBehindText {
		t.Fatalf("wall far behind the floor: %+v", s)
	}
}

func TestBadFutureFloorDoesNotBlockTLS(t *testing.T) {
	dir := floorDir(t)
	future := sane.Add(180 * 24 * time.Hour)
	writeFloor(t, dir, future.Unix())
	f := &fakeClocks{wall: sane}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if !c.TrustTime().Equal(sane) {
		t.Fatal("certificates checked at the stored floor:", c.TrustTime())
	}
	if !c.Now().Equal(future) {
		t.Fatal("signed-token clock below the floor before signed time")
	}
	// Signed time that agrees with the system clock heals the floor.
	c.Observe(sane.Unix() + 2)
	if fl, _ := c.Floor(); fl != sane.Unix()+2 || readFloor(t, dir) != sane.Unix()+2 || c.Now().Unix() != sane.Unix()+2 {
		t.Fatal("floor not healed:", fl, readFloor(t, dir))
	}
	if c.TrustTime().Unix() != sane.Unix()+2 {
		t.Fatal("trust time below the corroborated floor:", c.TrustTime())
	}
}

// Signed time that disagrees with a plausible system clock corrects Now,
// never below the floor, but is not used for certificates and is never
// written as the floor.
func TestSignedTimeDisagreeingWithSaneClock(t *testing.T) {
	for name, signed := range map[string]time.Time{
		"bad future":       sane.Add(180 * 24 * time.Hour),
		"far below floor":  sane.Add(-2 * time.Hour),
		"just past ahead":  sane.Add(ClockWrong + time.Second),
		"just past behind": sane.Add(-ClockWrong - time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			dir := floorDir(t)
			writeFloor(t, dir, sane.Unix())
			f := &fakeClocks{wall: sane}
			c := openSignedClock(dir, f.Wall, f.Mono, nil)
			c.Observe(signed.Unix())
			if fl, _ := c.Floor(); fl != sane.Unix() || readFloor(t, dir) != sane.Unix() {
				t.Fatal("untrusted signed time moved the floor:", fl, readFloor(t, dir))
			}
			if !c.TrustTime().Equal(sane) {
				t.Fatal("untrusted signed time used for certificates:", c.TrustTime())
			}
			if want := later(signed, sane); !c.Ready() || !c.Now().Equal(want) {
				t.Fatal("Now:", c.Now(), "want", want)
			}
		})
	}
	for name, signed := range map[string]time.Time{
		"at limit ahead":  sane.Add(ClockWrong),
		"at limit behind": sane.Add(-ClockWrong),
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeClocks{wall: sane}
			c := openSignedClock("", f.Wall, f.Mono, nil)
			c.Observe(signed.Unix())
			if fl, _ := c.Floor(); !c.Ready() || c.Now().Unix() != signed.Unix() || !c.TrustTime().Equal(later(sane, signed)) || fl != signed.Unix() {
				t.Fatal("agreeing signed time not applied")
			}
		})
	}
}

// A NAS without NTP: its clock is plausible but ten minutes off. Proofs
// and tokens use signed time; certificates use the system clock; nothing
// is persisted from the disagreeing time; the UI says the clock is wrong.
func TestSkewedPlausibleClockCorrected(t *testing.T) {
	for _, skew := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		dir := floorDir(t)
		f := &fakeClocks{wall: sane.Add(skew)}
		c := openSignedClock(dir, f.Wall, f.Mono, nil)
		c.Observe(sane.Unix())
		f.run(time.Minute)
		if got := c.Now(); !got.Equal(sane.Add(time.Minute)) {
			t.Fatalf("skew %s: Now %v", skew, got)
		}
		if got := c.TrustTime(); !got.Equal(sane.Add(skew + time.Minute)) {
			t.Fatalf("skew %s: TrustTime %v", skew, got)
		}
		if _, err := os.Stat(filepath.Join(dir, TimeFloorFile)); !os.IsNotExist(err) {
			t.Fatalf("skew %s: floor persisted from an untrusted time", skew)
		}
		if s := c.Status(); s.State != ClockIsWrong || s.Text != clockWrongText {
			t.Fatalf("skew %s: %+v", skew, s)
		}
	}
}

// The floor holds Now against a signed time below it while the system
// clock agrees with the floor.
func TestSignedTimeBelowFloorHoldsNow(t *testing.T) {
	dir := floorDir(t)
	writeFloor(t, dir, sane.Unix())
	f := &fakeClocks{wall: sane}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	c.Observe(sane.Unix() - 3600)
	f.run(10 * time.Second)
	if got := c.Now().Unix(); got != sane.Unix() {
		t.Fatal("Now below the floor:", got)
	}
	if got := c.TrustTime(); !got.Equal(sane.Add(10 * time.Second)) {
		t.Fatal(got)
	}
}

func TestNoRealTimeClockUsesFloorAndSignedTime(t *testing.T) {
	dir := floorDir(t)
	writeFloorAs(t, dir, sane.Unix(), true)
	f := &fakeClocks{wall: time.Unix(86400, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if c.TrustTime().Unix() != sane.Unix() || c.Now().Unix() != sane.Unix() {
		t.Fatal("corroborated floor not used without a real-time clock:", c.TrustTime())
	}
	c.Observe(sane.Unix() + 3600)
	f.run(10 * time.Second)
	if c.TrustTime().Unix() != sane.Unix()+3610 || c.Now().Unix() != sane.Unix()+3610 {
		t.Fatal("signed time not used without a real-time clock:", c.TrustTime())
	}
	if fl, _ := c.Floor(); fl != sane.Unix()+3600 || readFloor(t, dir) != sane.Unix()+3600 {
		t.Fatal("trusted time did not raise the floor:", fl)
	}
	var ff floorFile
	b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
	_ = json.Unmarshal(b, &ff)
	if ff.Corroborated != sane.Unix() {
		t.Fatal("corroborated floor changed without a plausible clock:", ff.Corroborated)
	}
}

// Without a real-time clock, signed time below MinPlausible or far below
// the floor is neither trusted nor persisted; Now stays at the floor.
func TestNoRealTimeClockRefusesLowSignedTime(t *testing.T) {
	for name, signed := range map[string]int64{
		"below MinPlausible": MinPlausible.Unix() - 1,
		"far below floor":    sane.Unix() - clockWrongSec - 1,
	} {
		t.Run(name, func(t *testing.T) {
			dir := floorDir(t)
			writeFloorAs(t, dir, sane.Unix(), true)
			f := &fakeClocks{wall: time.Unix(86400, 0)}
			c := openSignedClock(dir, f.Wall, f.Mono, nil)
			c.Observe(signed)
			if fl, _ := c.Floor(); fl != sane.Unix() || readFloor(t, dir) != sane.Unix() {
				t.Fatal("low signed time moved the floor:", fl)
			}
			if c.Now().Unix() != sane.Unix() || c.TrustTime().Unix() != sane.Unix() {
				t.Fatal("clock below the floor:", c.Now(), c.TrustTime())
			}
		})
	}
	// With no floor, a time below MinPlausible is not trusted either.
	dir := floorDir(t)
	f := &fakeClocks{wall: time.Unix(86400, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	c.Observe(MinPlausible.Unix() - 3600)
	if _, err := os.Stat(filepath.Join(dir, TimeFloorFile)); !os.IsNotExist(err) {
		t.Fatal("time below MinPlausible persisted")
	}
	if !c.TrustTime().Equal(time.Unix(86400, 0)) {
		t.Fatal("untrusted time used for certificates")
	}
}

// Without a real-time clock an uncorroborated floor sets the certificate
// time; one retry goes to the corroborated floor, or the system clock.
func TestUncorroboratedFloorWithoutRTC(t *testing.T) {
	future := sane.Add(180 * 24 * time.Hour)
	f := &fakeClocks{wall: time.Unix(86400, 0)}

	dir := floorDir(t)
	writeFloor(t, dir, future.Unix())
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if !c.TrustTime().Equal(future) {
		t.Fatal("uncorroborated floor not used:", c.TrustTime())
	}
	if rt, ok := c.RetryTime(); !ok || !rt.Equal(time.Unix(86400, 0)) {
		t.Fatal("retry without a corroborated floor:", rt, ok)
	}

	d := floorDir(t)
	b, _ := json.Marshal(floorFile{Schema: 1, Floor: future.Unix(), Corroborated: sane.Unix()})
	if err := os.WriteFile(filepath.Join(d, TimeFloorFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r := openSignedClock(d, f.Wall, f.Mono, nil)
	if rt, ok := r.RetryTime(); !ok || rt.Unix() != sane.Unix() {
		t.Fatal("retry not at the corroborated floor:", rt, ok)
	}
	// No retry once trusted time is known, or with a plausible clock.
	r.Observe(future.Unix())
	if _, ok := r.RetryTime(); ok {
		t.Fatal("retry offered with trusted time")
	}
	g := &fakeClocks{wall: sane}
	if _, ok := openSignedClock(dir, g.Wall, g.Mono, nil).RetryTime(); ok {
		t.Fatal("retry offered with a plausible clock")
	}
}

// Stolen key plus spoofed NTP: a plausible clock set back with a signed
// time agreeing with it cannot lower the corroborated floor or drag Now
// back past the trusted progression of this run.
func TestCorroboratedFloorNeverLowered(t *testing.T) {
	dir := floorDir(t)
	f := &fakeClocks{wall: sane}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	c.Observe(sane.Unix())
	f.run(time.Hour)
	f.setWall(sane.Add(-2 * time.Hour))
	c.Observe(sane.Add(-2 * time.Hour).Unix())
	if fl, _ := c.Floor(); fl != sane.Unix() || readFloor(t, dir) != sane.Unix() {
		t.Fatal("floor lowered:", fl)
	}
	var ff floorFile
	b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
	_ = json.Unmarshal(b, &ff)
	if ff.Corroborated != sane.Unix() {
		t.Fatal("corroborated floor lowered:", ff.Corroborated)
	}
	if got := c.Now(); got.Before(sane.Add(time.Hour - ClockWrong)) {
		t.Fatal("Now dragged back past the trusted progression:", got)
	}
	if got := c.TrustTime(); got.Before(sane) {
		t.Fatal("certificate time below the corroborated floor:", got)
	}
	r := openSignedClock(dir, f.Wall, f.Mono, nil)
	if got := r.Now(); got.Before(sane) {
		t.Fatal("after restart:", got)
	}
}

// localCert is a server certificate valid only around sane.
func localCert(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: sane.Add(-24 * time.Hour), NotAfter: sane.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, pool
}

func handshakeAt(srv *httptest.Server, roots *x509.CertPool, at func() time.Time) error {
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Time: at}}}
	resp, err := cl.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

// A Pi with a stored corroborated floor boots at 1970, connects at its
// floor, takes signed time, and keeps its corroborated floor.
func TestPiBootsWithoutRTC(t *testing.T) {
	srv, roots := localCert(t)
	dir := floorDir(t)
	writeFloorAs(t, dir, sane.Unix(), true)
	f := &fakeClocks{wall: time.Unix(0, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if err := handshakeAt(srv, roots, c.TrustTime); err != nil {
		t.Fatal("no connection at boot:", err)
	}
	c.Observe(sane.Unix() + 600)
	if err := handshakeAt(srv, roots, c.TrustTime); err != nil {
		t.Fatal("no connection after signed time:", err)
	}
	var ff floorFile
	b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
	_ = json.Unmarshal(b, &ff)
	if ff.Floor != sane.Unix()+600 || ff.Corroborated != sane.Unix() {
		t.Fatalf("floors after signed time: %+v", ff)
	}
	r := openSignedClock(dir, f.Wall, f.Mono, nil)
	if err := handshakeAt(srv, roots, r.TrustTime); err != nil {
		t.Fatal("no connection on the next boot:", err)
	}
}

// A fresh device without a real-time clock checks at its system clock
// until it has a floor; then it connects.
func TestFreshDeviceWithoutRTC(t *testing.T) {
	srv, roots := localCert(t)
	dir := floorDir(t)
	f := &fakeClocks{wall: time.Unix(0, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	if err := handshakeAt(srv, roots, c.TrustTime); err == nil {
		t.Fatal("a 1970 clock verified a current certificate")
	}
	writeFloor(t, dir, sane.Unix())
	r := openSignedClock(dir, f.Wall, f.Mono, nil)
	if err := handshakeAt(srv, roots, r.TrustTime); err != nil {
		t.Fatal("no connection once the floor is set:", err)
	}
}

// A plausible clock stepped back a year never checks certificates below
// the corroborated floor.
func TestPlausibleClockSteppedBackKeepsFloor(t *testing.T) {
	dir := floorDir(t)
	f := &fakeClocks{wall: sane}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	c.Observe(sane.Unix())
	f.setWall(sane.Add(-365 * 24 * time.Hour))
	if got := c.TrustTime(); got.Before(sane) {
		t.Fatal("trust time below the floor:", got)
	}
	r := openSignedClock(dir, f.Wall, f.Mono, nil)
	if got := r.TrustTime(); got.Unix() != sane.Unix() {
		t.Fatal("after restart:", got)
	}
}

// A replayed or stale signed time cannot drag Now back.
func TestSignedTimeCannotFreezeNow(t *testing.T) {
	for name, w := range map[string]time.Time{"plausible clock": sane, "no real-time clock": time.Unix(86400, 0)} {
		t.Run(name, func(t *testing.T) {
			f := &fakeClocks{wall: w}
			c := openSignedClock("", f.Wall, f.Mono, nil)
			c.Observe(sane.Unix())
			f.run(time.Hour)
			c.Observe(sane.Unix() + 1)
			if got := c.Now().Unix(); got != sane.Unix()+3600 {
				t.Fatal("Now dragged back:", got)
			}
			// A small step back within ClockWrong is taken.
			c.Observe(sane.Unix() + 3600 - clockWrongSec)
			if got := c.Now().Unix(); got != sane.Unix()+3600-clockWrongSec {
				t.Fatal("small correction not taken:", got)
			}
		})
	}
}

// One bad far-future signed time is followed by correct ones: Now recovers.
func TestNowRecoversFromBadFutureTime(t *testing.T) {
	for name, skew := range map[string]time.Duration{"right clock": 0, "skewed clock": 10 * time.Minute} {
		t.Run(name, func(t *testing.T) {
			f := &fakeClocks{wall: sane.Add(skew)}
			c := openSignedClock(floorDir(t), f.Wall, f.Mono, nil)
			c.Observe(sane.Add(180 * 24 * time.Hour).Unix())
			if !c.Now().Equal(sane.Add(180 * 24 * time.Hour)) {
				t.Fatal("future time not followed")
			}
			f.run(time.Minute)
			c.Observe(sane.Unix() + 60)
			if got := c.Now().Unix(); got != sane.Unix()+60 {
				t.Fatal("Now stuck in the future:", got)
			}
			if fl, _ := c.Floor(); fl > sane.Unix()+60 {
				t.Fatal("floor kept the future time:", fl)
			}
		})
	}
}

// A real TLS handshake: a stored floor past the certificate's expiry does
// not stop a machine with a right clock from connecting.
func TestFloorPastCertificateExpiryStillConnects(t *testing.T) {
	if time.Now().Before(MinPlausible) {
		t.Skip("host clock below MinPlausible")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	dir := floorDir(t)
	writeFloor(t, dir, time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC).Unix()) // the test certificate ends in 2084
	c := openSignedClock(dir, nil, nil, nil)
	get := func(at func() time.Time) error {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Time: at}}}
		resp, err := cl.Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(c.TrustTime); err != nil {
		t.Fatal("trust time:", err)
	}
	if err := get(c.Now); err == nil {
		t.Fatal("the floor clock should fail this certificate")
	}
}

func TestTrustBoundariesWithoutRTC(t *testing.T) {
	f := &fakeClocks{wall: time.Unix(86400, 0)}
	c := openSignedClock("", f.Wall, f.Mono, nil)
	c.Observe(MinPlausible.Unix())
	if fl, _ := c.Floor(); fl != MinPlausible.Unix() {
		t.Fatal("MinPlausible itself not trusted:", fl)
	}

	for name, c := range map[string]struct {
		signed  int64
		trusted bool
	}{
		"at the leeway below the floor":    {sane.Unix() - clockWrongSec, true},
		"just past the leeway below floor": {sane.Unix() - clockWrongSec - 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			// The corroborated floor is above both times, so neither lowers
			// the floor; only the leeway decides.
			dir := floorDir(t)
			writeFloors(t, dir, sane.Unix(), sane.Unix()-200)
			r := openSignedClock(dir, f.Wall, f.Mono, nil)
			r.Observe(c.signed)
			if r.tset != c.trusted {
				t.Fatalf("trusted %v, want %v", r.tset, c.trusted)
			}
			if fl, _ := r.Floor(); fl != sane.Unix() {
				t.Fatal("floor moved:", fl)
			}
		})
	}
}

// A time only exactly ClockWrong closer to a skewed system clock does not
// replace an older source; one a second closer does.
func TestCloserBoundary(t *testing.T) {
	for _, tc := range []struct {
		signed int64
		takes  bool
	}{{sane.Unix() - 700, false}, {sane.Unix() - 699, true}} {
		f := &fakeClocks{wall: sane}
		c := openSignedClock("", f.Wall, f.Mono, nil)
		c.Observe(sane.Unix() + 1000)
		c.Observe(tc.signed)
		if got := c.Now().Unix() == tc.signed; got != tc.takes {
			t.Fatalf("signed %d: taken %v, want %v", tc.signed, got, tc.takes)
		}
	}
}

// Without a real-time clock one bad far-future signed time is undone by
// the next correct ones, down to the corroborated floor and never below.
func TestNoRealTimeClockRecoversFromBadFutureTime(t *testing.T) {
	dir := floorDir(t)
	writeFloorAs(t, dir, sane.Unix(), true)
	f := &fakeClocks{wall: time.Unix(0, 0)}
	c := openSignedClock(dir, f.Wall, f.Mono, nil)
	bad := sane.Add(180 * 24 * time.Hour).Unix()
	c.Observe(bad)
	if fl, _ := c.Floor(); fl != bad || c.Now().Unix() != bad {
		t.Fatal("bad future time not taken:", fl)
	}
	f.run(time.Minute)
	c.Observe(sane.Unix() + 600)
	if fl, _ := c.Floor(); fl != sane.Unix()+600 || readFloor(t, dir) != sane.Unix()+600 || c.Now().Unix() != sane.Unix()+600 {
		t.Fatal("not recovered:", fl, c.Now().Unix())
	}
	if c.TrustTime().Unix() != sane.Unix()+600 {
		t.Fatal("certificate time not recovered:", c.TrustTime())
	}
	f.run(time.Minute)
	c.Observe(sane.Unix() + 660)
	// Below the corroborated floor nothing moves.
	c.Observe(sane.Unix() - 3600)
	if fl, _ := c.Floor(); fl != sane.Unix()+660 || c.Now().Unix() < sane.Unix()+660 {
		t.Fatal("moved below the corroborated floor:", fl, c.Now().Unix())
	}
	var ff floorFile
	b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
	_ = json.Unmarshal(b, &ff)
	if ff.Corroborated != sane.Unix() {
		t.Fatal("corroborated floor changed:", ff.Corroborated)
	}

	// With no corroborated floor the floor still comes down, to the new time.
	d := floorDir(t)
	r := openSignedClock(d, f.Wall, f.Mono, nil)
	r.Observe(bad)
	r.Observe(sane.Unix())
	if fl, _ := r.Floor(); fl != sane.Unix() || r.Now().Unix() != sane.Unix() {
		t.Fatal("not recovered without a corroborated floor:", fl, r.Now().Unix())
	}
}

// Edge cases found by mutation testing of the clock rules.
func TestClockRuleEdges(t *testing.T) {
	rtcLess := func() *fakeClocks { return &fakeClocks{wall: time.Unix(86400, 0)} }

	t.Run("MinPlausible itself is plausible", func(t *testing.T) {
		f := &fakeClocks{wall: MinPlausible}
		if s := openSignedClock("", f.Wall, f.Mono, nil).Status(); s.Text != "" {
			t.Fatalf("%+v", s)
		}
	})
	t.Run("stored corroborated floor above the floor", func(t *testing.T) {
		dir := floorDir(t)
		writeFloors(t, dir, 1700000000, sane.Unix())
		if fl, _ := openSignedClock(dir, nil, nil, nil).Floor(); fl != sane.Unix() {
			t.Fatal(fl)
		}
	})
	t.Run("far below a corroborated floor is not trusted", func(t *testing.T) {
		dir := floorDir(t)
		writeFloorAs(t, dir, sane.Unix(), true)
		f := rtcLess()
		c := openSignedClock(dir, f.Wall, f.Mono, nil)
		c.Observe(sane.Unix() - 3600)
		if c.tset || c.srcTrust {
			t.Fatal("trusted")
		}
	})
	t.Run("recovery reaches exactly the corroborated floor", func(t *testing.T) {
		dir := floorDir(t)
		writeFloors(t, dir, sane.Add(24*time.Hour).Unix(), sane.Unix())
		f := rtcLess()
		c := openSignedClock(dir, f.Wall, f.Mono, nil)
		c.Observe(sane.Unix())
		if fl, _ := c.Floor(); fl != sane.Unix() || !c.tset {
			t.Fatal("not lowered to the corroborated floor:", fl)
		}
	})
	t.Run("at the leeway below an uncorroborated floor nothing is lowered", func(t *testing.T) {
		dir := floorDir(t)
		writeFloor(t, dir, sane.Unix())
		f := rtcLess()
		c := openSignedClock(dir, f.Wall, f.Mono, nil)
		c.Observe(sane.Unix() - clockWrongSec)
		if fl, _ := c.Floor(); fl != sane.Unix() {
			t.Fatal("lowered:", fl)
		}
	})
	t.Run("an agreeing time never lowers the floor below the corroborated floor", func(t *testing.T) {
		dir := floorDir(t)
		writeFloors(t, dir, sane.Add(24*time.Hour).Unix(), sane.Unix())
		f := &fakeClocks{wall: sane.Add(-1000 * time.Second)}
		c := openSignedClock(dir, f.Wall, f.Mono, nil)
		c.Observe(sane.Unix() - 1000)
		if fl, _ := c.Floor(); fl != sane.Unix() || readFloor(t, dir) != sane.Unix() {
			t.Fatal("floor below the corroborated floor:", fl)
		}
	})
	t.Run("a small corroboration step is persisted", func(t *testing.T) {
		dir := floorDir(t)
		writeFloor(t, dir, sane.Unix())
		f := &fakeClocks{wall: sane.Add(10 * time.Second)}
		c := openSignedClock(dir, f.Wall, f.Mono, nil)
		c.Observe(sane.Unix() + 10)
		var ff floorFile
		b, _ := os.ReadFile(filepath.Join(dir, TimeFloorFile))
		_ = json.Unmarshal(b, &ff)
		if ff.Corroborated != sane.Unix()+10 {
			t.Fatalf("%+v", ff)
		}
	})
	t.Run("no retry at a corroborated floor or a floor behind the clock", func(t *testing.T) {
		f := rtcLess()
		dir := floorDir(t)
		writeFloorAs(t, dir, sane.Unix(), true)
		if _, ok := openSignedClock(dir, f.Wall, f.Mono, nil).RetryTime(); ok {
			t.Fatal("retry at a corroborated floor")
		}
		d := floorDir(t)
		writeFloor(t, d, 1000)
		if _, ok := openSignedClock(d, f.Wall, f.Mono, nil).RetryTime(); ok {
			t.Fatal("retry with a floor behind the clock")
		}
	})
	t.Run("a clock jump drops trusted time for certificates", func(t *testing.T) {
		f := &fakeClocks{wall: sane}
		c := openSignedClock("", f.Wall, f.Mono, nil)
		c.Observe(sane.Unix())
		f.setWall(sane.Add(2 * time.Hour))
		if got := c.TrustTime(); !got.Equal(sane.Add(2 * time.Hour)) {
			t.Fatal("stale trusted time used:", got)
		}
	})
	t.Run("an implausible clock with a floor behind it is wrong", func(t *testing.T) {
		dir := floorDir(t)
		writeFloor(t, dir, 1000)
		f := rtcLess()
		if s := openSignedClock(dir, f.Wall, f.Mono, nil).Status(); s.State != ClockIsWrong {
			t.Fatalf("%+v", s)
		}
	})
}
