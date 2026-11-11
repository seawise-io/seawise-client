// Package appsync keeps the agent's app list in sync with the v2 device
// API: upserts by local_id, tombstones, idempotency keys and a persistent
// outbox. It never deletes an app because the server did not list it.
package appsync

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

var (
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// ValidLocalID reports whether s is a lower-case UUID.
func ValidLocalID(s string) bool { return uuidRe.MatchString(s) }

// NewLocalID returns a random lower-case UUID (version 4).
func NewLocalID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// newKey returns an Idempotency-Key: 16 random bytes in lower-case hex.
func newKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
