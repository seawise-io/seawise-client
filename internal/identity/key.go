// Package identity holds the device key: an Ed25519 key generated on this
// machine whose private half never leaves it. Only the public key, its key
// ID and its fingerprint are ever shown or sent.
package identity

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/seawise/client/internal/protocol"
)

var (
	ErrDestroyed = errors.New("device key was destroyed")
	errHashOpts  = errors.New("device key signs pure Ed25519 only")
)

// Key is a device key. Its zero value is not usable; keys come from a
// Keystore. Every formatting and encoding path renders public data only.
type Key struct{ d *keyData }

type keyData struct {
	mu        sync.RWMutex
	priv      ed25519.PrivateKey // nil once destroyed
	pub       ed25519.PublicKey
	createdAt time.Time
}

// PublicInfo is everything about a key that may be shown or sent.
type PublicInfo struct {
	PublicKey   string `json:"public_key"`
	KeyID       string `json:"key_id"`
	Fingerprint string `json:"fingerprint"`
}

func generate(now time.Time) (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	return newKey(priv, pub, now)
}

// keyFromSeed derives a key; the caller clears seed.
func keyFromSeed(seed []byte, createdAt time.Time) (*Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed has %d bytes", ErrCorrupt, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return newKey(priv, priv.Public().(ed25519.PublicKey), createdAt)
}

func newKey(priv ed25519.PrivateKey, pub ed25519.PublicKey, createdAt time.Time) (*Key, error) {
	if err := protocol.CheckPublicKey(pub); err != nil {
		clear(priv)
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if protocol.IsTestVectorKey(protocol.KeyID(pub)) {
		clear(priv)
		return nil, ErrTestKey
	}
	return &Key{d: &keyData{priv: priv, pub: slices.Clone(pub), createdAt: createdAt.UTC().Truncate(time.Second)}}, nil
}

// Public implements crypto.Signer.
func (k Key) Public() crypto.PublicKey { return k.PublicKey() }

// PublicKey returns a copy of the public key.
func (k Key) PublicKey() ed25519.PublicKey { return slices.Clone(k.d.pub) }

// Sign implements crypto.Signer for pure Ed25519. Pre-hashed and context
// variants are refused so the key cannot sign in another scheme.
func (k Key) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.Hash(0) {
		return nil, errHashOpts
	}
	if o, ok := opts.(*ed25519.Options); ok && (o.Hash != crypto.Hash(0) || o.Context != "") {
		return nil, errHashOpts
	}
	k.d.mu.RLock()
	defer k.d.mu.RUnlock()
	if k.d.priv == nil {
		return nil, ErrDestroyed
	}
	return ed25519.Sign(k.d.priv, msg), nil
}

// KeyID is the RFC 7638 thumbprint of the public key.
func (k Key) KeyID() string { return protocol.KeyID(k.d.pub) }

// Fingerprint is the SW-XXXX-XXXX-XXXX-XXXX display form.
func (k Key) Fingerprint() string { return protocol.Fingerprint(k.d.pub) }

// CreatedAt is when the key was generated, to the second.
func (k Key) CreatedAt() time.Time { return k.d.createdAt }

// Info returns the public view of the key for the UI and the API.
func (k Key) Info() PublicInfo {
	return PublicInfo{PublicKey: base64.RawURLEncoding.EncodeToString(k.d.pub), KeyID: k.KeyID(), Fingerprint: k.Fingerprint()}
}

func (k Key) String() string   { return "device key " + k.Fingerprint() }
func (k Key) GoString() string { return k.String() }

// Format renders every verb, including %#v and %x, as String.
func (k Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue keeps structured logs to the public view.
func (k Key) LogValue() slog.Value {
	return slog.GroupValue(slog.String("fingerprint", k.Fingerprint()), slog.String("key_id", k.KeyID()))
}

func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(k.Info()) }
func (k Key) MarshalText() ([]byte, error) { return []byte(k.Fingerprint()), nil }

// seed returns a copy of the private seed for the file backend; the caller
// clears it.
func (k Key) seed() ([]byte, error) {
	k.d.mu.RLock()
	defer k.d.mu.RUnlock()
	if k.d.priv == nil {
		return nil, ErrDestroyed
	}
	return k.d.priv.Seed(), nil
}

// destroy zeroes the private key. Go may have copied it elsewhere in
// memory (garbage collection, stack growth), so this is best effort.
func (k Key) destroy() {
	k.d.mu.Lock()
	defer k.d.mu.Unlock()
	clear(k.d.priv)
	k.d.priv = nil
}
