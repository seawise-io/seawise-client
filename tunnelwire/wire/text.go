package wire

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var (
	edgeIDRe = regexp.MustCompile(`^edge-[a-z]+-[a-z]+-[0-9]{1,4}$`)
	semverRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`)
)

// ValidEdgeID reports whether s is an edge id.
func ValidEdgeID(s string) bool { return len(s) <= MaxEdgeID && edgeIDRe.MatchString(s) }

// ValidAgentVersion reports whether s is a semver without build metadata,
// 1..32 bytes.
func ValidAgentVersion(s string) bool {
	return len(s) >= 1 && len(s) <= MaxAgentVersion && semverRe.MatchString(s)
}

// ValidToken reports whether s is 1..max bytes of [a-z0-9_.-].
func ValidToken(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// ValidKeyID reports whether s is a base64url SHA-256 thumbprint.
func ValidKeyID(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32 && !strings.ContainsAny(s, "\r\n")
}

// ValidCapabilities reports whether caps is a sorted list of unique tokens
// within the caps.
func ValidCapabilities(caps []string) bool {
	if len(caps) > MaxCapabilities {
		return false
	}
	for i, c := range caps {
		if !ValidToken(c, MaxCapabilityLen) {
			return false
		}
		if i > 0 && caps[i-1] >= c {
			return false
		}
	}
	return true
}

func isB64URL(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// ValidCompactJWS reports whether s has the shape of a compact JWS: three
// non-empty base64url segments, at most max bytes.
func ValidCompactJWS(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	dots, run := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if run == 0 {
				return false
			}
			dots++
			run = 0
		case isB64URL(c):
			run++
		default:
			return false
		}
	}
	return dots == 2 && run > 0
}

// validDetail reports whether s is printable ASCII within MaxDetail.
func validDetail(s string) bool {
	if len(s) > MaxDetail {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validNonce reports whether s is 0..256 NQCHAR (RFC 9449 section 8).
func validNonce(s string) bool {
	if len(s) > MaxDPoPNonce {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == 0x21 || c >= 0x23 && c <= 0x5b || c >= 0x5d && c <= 0x7e) {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
