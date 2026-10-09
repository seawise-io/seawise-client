package updatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Image is the only image a release manifest may name.
const Image = "ghcr.io/seawise-io/seawise-client"

var (
	semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$`)
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Release is a verified release manifest.
type Release struct {
	Channel string    `json:"channel"`
	Image   string    `json:"image"`
	Version string    `json:"version"`
	Digest  string    `json:"digest"`
	Expires time.Time `json:"expires"`
}

func parseManifest(b []byte, channel string) (*Release, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var m Release
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("release manifest: trailing data")
	}
	switch {
	case m.Channel != channel:
		return nil, fmt.Errorf("release manifest is for channel %q", m.Channel)
	case m.Image != Image:
		return nil, errors.New("release manifest names another image")
	case !semverRe.MatchString(m.Version):
		return nil, errors.New("release manifest version is not semver")
	case !digestRe.MatchString(m.Digest):
		return nil, errors.New("release manifest digest is invalid")
	case m.Expires.IsZero():
		return nil, errors.New("release manifest has no expiry")
	}
	return &m, nil
}

// newer reports whether candidate is a higher semver version than current.
// A current version that is not semver (such as "dev") never compares lower.
func newer(current, candidate string) bool {
	c, ok1 := parseSemver(strings.TrimPrefix(current, "v"))
	n, ok2 := parseSemver(candidate)
	return ok1 && ok2 && compareSemver(n, c) > 0
}

type semver struct {
	core [3]uint64
	pre  []string
}

func parseSemver(s string) (semver, bool) {
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return semver{}, false
	}
	var v semver
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return semver{}, false
		}
		v.core[i] = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

func compareSemver(a, b semver) int {
	for i := range a.core {
		if a.core[i] != b.core[i] {
			if a.core[i] > b.core[i] {
				return 1
			}
			return -1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := compareIdent(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) > len(b.pre):
		return 1
	case len(a.pre) < len(b.pre):
		return -1
	}
	return 0
}

func compareIdent(a, b string) int {
	na, ea := strconv.ParseUint(a, 10, 64)
	nb, eb := strconv.ParseUint(b, 10, 64)
	switch {
	case ea == nil && eb == nil:
		if na == nb {
			return 0
		}
		if na > nb {
			return 1
		}
		return -1
	case ea == nil:
		return -1
	case eb == nil:
		return 1
	}
	return strings.Compare(a, b)
}
