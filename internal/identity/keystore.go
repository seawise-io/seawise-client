package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/seawise/client/internal/protocol"
)

// Keystore backends.
const (
	BackendFile     = "file"
	BackendKeychain = "keychain"
	BackendDPAPI    = "dpapi"
	BackendTPM      = "tpm"
)

var (
	ErrNoKey       = errors.New("no device key")
	ErrKeyExists   = errors.New("a device key already exists")
	ErrCorrupt     = errors.New("device key store is corrupt")
	ErrClosed      = errors.New("keystore is closed")
	ErrUnsupported = fmt.Errorf("keystore backend not available in this build: %w", errors.ErrUnsupported)
	ErrTestKey     = errors.New("device key is a published test key")
)

// Keystore holds the current device key and, during a rotation, the
// pending one. Implementations never expose private key material.
type Keystore interface {
	Backend() string
	// Current returns the active key, or ErrNoKey.
	Current() (*Key, error)
	// Create generates the first key. It returns ErrKeyExists rather than
	// replace an identity.
	Create() (*Key, error)
	// Pending returns the rotation candidate, or ErrNoKey.
	Pending() (*Key, error)
	// BeginRotation creates the pending key, or returns the existing one so
	// a retried rotation uses the same key.
	BeginRotation() (*Key, error)
	// CommitRotation makes the pending key current and destroys the old one.
	CommitRotation() error
	// AbortRotation destroys the pending key, if any.
	AbortRotation() error
	// Close destroys keys held in memory.
	Close() error
}

// Open returns the keystore for backend. dir is the agent's locked v2
// state directory, used by the file backend. Native backends arrive with
// the native packages.
func Open(backend, dir string, now func() time.Time) (Keystore, error) {
	switch backend {
	case BackendFile:
		return OpenFile(dir, now)
	case BackendKeychain, BackendDPAPI, BackendTPM:
		return nil, fmt.Errorf("%s: %w", backend, ErrUnsupported)
	}
	return nil, fmt.Errorf("unknown keystore backend %q", backend)
}

// Rotate starts or resumes a rotation for serverID and returns the
// statement to send. The pending key's creation time is the statement's
// iat, so a retry yields the identical rotation. Call CommitRotation only
// after the server accepts it.
func Rotate(ks Keystore, serverID string) (protocol.Rotation, error) {
	cur, err := ks.Current()
	if err != nil {
		return protocol.Rotation{}, err
	}
	next, err := ks.BeginRotation()
	if err != nil {
		return protocol.Rotation{}, err
	}
	return protocol.NewRotation(cur, next, serverID, next.CreatedAt().Unix())
}

var (
	// ErrRepairNeeded means the device key is revoked and no pending key
	// was accepted: the agent must pair again.
	ErrRepairNeeded = errors.New("device key revoked; pair this device again")
	// ErrKeyLost means the agent is paired but its key is gone. A new key
	// would be a different identity, so none is created.
	ErrKeyLost = errors.New("device is paired but its key is missing; pair this device again")
)

// RecoverRevoked handles the server reporting the current key as revoked.
// If a rotation is pending, the server may have accepted it before the
// agent could commit: probe sends one request signed with the pending key,
// and on success the rotation is committed. The current key is never
// replaced otherwise.
func RecoverRevoked(ks Keystore, probe func(*Key) error) error {
	next, err := ks.Pending()
	if errors.Is(err, ErrNoKey) {
		return ErrRepairNeeded
	}
	if err != nil {
		return err
	}
	if err := probe(next); err != nil {
		return fmt.Errorf("%w: pending key not accepted: %w", ErrRepairNeeded, err)
	}
	return ks.CommitRotation()
}

// EnsureKey returns the current key, creating one only for an agent that
// is not paired.
func EnsureKey(ks Keystore, paired bool) (*Key, error) {
	k, err := ks.Current()
	switch {
	case err == nil:
		return k, nil
	case !errors.Is(err, ErrNoKey):
		return nil, err
	case paired:
		return nil, ErrKeyLost
	}
	return ks.Create()
}
