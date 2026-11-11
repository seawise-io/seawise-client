package updatecheck

import (
	"strings"
	"testing"
	"time"
)

const goodDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func manifestJSON(channel, version, expires string) string {
	return `{"channel":"` + channel + `","image":"ghcr.io/seawise-io/seawise-client","version":"` + version +
		`","digest":"` + goodDigest + `","expires":"` + expires + `"}`
}

func TestParseManifest(t *testing.T) {
	m, err := parseManifest([]byte(manifestJSON("stable", "2.1.0", "2031-01-01T00:00:00Z")), "stable")
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "2.1.0" || m.Digest != goodDigest || !m.Expires.Equal(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", m)
	}
	bad := map[string]string{
		"channel":   manifestJSON("beta", "2.1.0", "2031-01-01T00:00:00Z"),
		"version":   manifestJSON("stable", "2.1", "2031-01-01T00:00:00Z"),
		"leading 0": manifestJSON("stable", "2.01.0", "2031-01-01T00:00:00Z"),
		"build":     manifestJSON("stable", "2.1.0+x", "2031-01-01T00:00:00Z"),
		"expires":   manifestJSON("stable", "2.1.0", "soon"),
		"image":     strings.Replace(manifestJSON("stable", "2.1.0", "2031-01-01T00:00:00Z"), "seawise-io/seawise-client", "evil/client", 1),
		"digest":    strings.Replace(manifestJSON("stable", "2.1.0", "2031-01-01T00:00:00Z"), goodDigest, "sha256:abc", 1),
		"json":      `{"channel":`,
		"trailing":  manifestJSON("stable", "2.1.0", "2031-01-01T00:00:00Z") + "{}",
	}
	for name, raw := range bad {
		if _, err := parseManifest([]byte(raw), "stable"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"v2.0.0", "2.0.1", true},
		{"v2.0.0", "2.0.0", false},
		{"2.1.0", "2.0.9", false},
		{"v2.0.0-beta.1", "2.0.0", true},
		{"v2.0.0-beta.1", "2.0.0-beta.2", true},
		{"v2.0.0-beta.2", "2.0.0-beta.10", true},
		{"v2.0.0-beta.10", "2.0.0-beta.2", false},
		{"v2.0.0-alpha", "2.0.0-alpha.1", true},
		{"v2.0.0-beta", "2.0.0-alpha.9", false},
		{"v2.0.0-1", "2.0.0-alpha", true},
		{"v2.0.0", "2.0.0-rc.1", false},
		{"dev", "9.9.9", false},
		{"", "2.0.0", false},
		{"v2.9.0", "10.0.0", true},
	}
	for _, c := range cases {
		if got := newer(c.cur, c.cand); got != c.want {
			t.Errorf("newer(%q, %q) = %v", c.cur, c.cand, got)
		}
	}
}
