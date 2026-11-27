package session

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// The package tests use fixed times from 2023 on; they count as plausible
// system clocks here.
func TestMain(m *testing.M) {
	MinPlausible = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	os.Exit(m.Run())
}

func TestMinPlausibleNeverAfterBuild(t *testing.T) {
	build := time.Date(2027, time.March, 4, 5, 6, 7, 0, time.UTC)
	epoch := strconv.FormatInt(build.Unix(), 10)
	for name, c := range map[string]struct {
		epoch string
		vcs   time.Time
		want  time.Time
	}{
		"ldflags epoch":       {epoch, time.Time{}, build.Add(-plausibleMargin)},
		"epoch wins over vcs": {epoch, build.Add(24 * time.Hour), build.Add(-plausibleMargin)},
		"vcs time":            {"", build, build.Add(-plausibleMargin)},
		"bad epoch, vcs time": {"x", build, build.Add(-plausibleMargin)},
		"zero epoch":          {"0", time.Time{}, fallbackPlausible},
		"nothing":             {"", time.Time{}, fallbackPlausible},
	} {
		got := minPlausible(c.epoch, c.vcs)
		if !got.Equal(c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
		if !c.vcs.IsZero() && got.After(c.vcs) || c.epoch == epoch && got.After(build) {
			t.Errorf("%s: after the build time", name)
		}
	}
	if fallbackPlausible.After(time.Now()) {
		t.Error("fallback is in the future")
	}
}
