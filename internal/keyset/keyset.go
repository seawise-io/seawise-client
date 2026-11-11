// Package keyset keeps the agent's SeaWise key set: verified against the
// pinned roots, never rolled back, stored privately. It never expires:
// the last verified set stays in use through outages of any length.
package keyset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/seawise/client/internal/protocol"
	"github.com/seawise/client/internal/store"
)

// StateFile holds the accepted key set and its floor; FloorFile a copy of
// the TUF rollback floor, kept apart from the update state.
const (
	StateFile = "keyset.json"
	FloorFile = "tuf-floor.json"
)

// Floor is the highest verified version of each TUF top-level role.
type Floor struct {
	Root      int64 `json:"root"`
	Timestamp int64 `json:"timestamp"`
	Snapshot  int64 `json:"snapshot"`
	Targets   int64 `json:"targets"`
}

// HoldMissing is the dial hold while no key set is verified.
const HoldMissing = "keyset_missing"

const maxRoots = 2

var (
	ErrNotConfigured = errors.New("no key-set roots in this build")
	ErrTestRoot      = errors.New("pinned key-set root is a test key")
)

//go:embed roots/production.json
var productionRoots []byte

// Pinned returns the key-set roots built into this binary (empty: none).
func Pinned() []byte { return bytes.TrimSpace(productionRoots) }

// ParseRoots reads {"roots":["<x>",...]}: one or two distinct keys. Empty
// input is no roots.
func ParseRoots(b []byte) ([]ed25519.PublicKey, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f struct {
		Roots []string `json:"roots"`
	}
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("key-set roots: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("key-set roots: trailing data")
	}
	if len(f.Roots) == 0 || len(f.Roots) > maxRoots {
		return nil, fmt.Errorf("key-set roots: want 1 to %d keys", maxRoots)
	}
	out := make([]ed25519.PublicKey, 0, len(f.Roots))
	seen := map[string]bool{}
	for _, x := range f.Roots {
		p, err := protocol.ParsePublicKey(x)
		if err != nil {
			return nil, fmt.Errorf("key-set roots: %w", err)
		}
		if seen[x] {
			return nil, errors.New("key-set roots: duplicate key")
		}
		seen[x] = true
		out = append(out, p)
	}
	return out, nil
}

// Config configures a Manager.
type Config struct {
	Dir            string
	Roots          []ed25519.PublicKey
	AllowTestRoots bool
	Now            func() time.Time
	Logger         *slog.Logger
}

// Status is the key set as the status API shows it.
type Status struct {
	Version    int64     `json:"version,omitempty"`
	Digest     string    `json:"digest,omitempty"`
	VerifiedAt time.Time `json:"verified_at,omitzero"`
	Hold       string    `json:"hold,omitempty"`
}

type stored struct {
	Schema     int       `json:"schema"`
	Token      string    `json:"token"`
	Version    int64     `json:"version"`
	Digest     string    `json:"digest"`
	VerifiedAt time.Time `json:"verified_at"`
}

// Manager holds the current key set.
type Manager struct {
	cfg Config
	log *slog.Logger

	mu     sync.Mutex
	ks     *protocol.KeySet
	floor  stored // highest accepted; kept even when the set is unusable
	digest [32]byte
	tuf    Floor
}

// New checks the roots and loads the stored key set.
func New(cfg Config) (*Manager, error) {
	if len(cfg.Roots) == 0 {
		return nil, ErrNotConfigured
	}
	for _, r := range cfg.Roots {
		if err := protocol.CheckPublicKey(r); err != nil {
			return nil, fmt.Errorf("key-set root: %w", err)
		}
		if protocol.IsTestVectorKey(protocol.KeyID(r)) && !cfg.AllowTestRoots {
			return nil, ErrTestRoot
		}
	}
	if cfg.Dir == "" {
		return nil, errors.New("key-set folder not set")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := store.CheckDir(cfg.Dir); err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, log: cfg.Logger.With("component", "keyset")}
	m.load()
	m.loadFloor()
	return m, nil
}

func (m *Manager) loadFloor() {
	b, err := store.ReadOwned(filepath.Join(m.cfg.Dir, FloorFile))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var f Floor
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		err = dec.Decode(&f)
	}
	if err == nil {
		err = f.check()
	}
	if err != nil {
		m.log.Warn("stored TUF floor copy not used", "error", err)
		return
	}
	m.tuf = f
}

func (f Floor) check() error {
	if f.Root < 0 || f.Timestamp < 0 || f.Snapshot < 0 || f.Targets < 0 {
		return errors.New("negative TUF floor")
	}
	return nil
}

// TUFFloor is the stored copy of the TUF rollback floor.
func (m *Manager) TUFFloor() Floor {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tuf
}

// SetTUFFloor replaces the copy with the floor of the latest verified
// metadata, which may be lower after a key rotation reset a role.
func (m *Manager) SetTUFFloor(f Floor) error {
	if err := f.check(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(filepath.Join(m.cfg.Dir, FloorFile), b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	m.tuf = f
	return nil
}

func (m *Manager) load() {
	b, err := store.ReadOwned(filepath.Join(m.cfg.Dir, StateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		m.log.Warn("stored key set not used", "error", err)
		return
	}
	s, err := parseStored(b)
	if err != nil {
		m.log.Warn("stored key set not used", "error", err)
		return
	}
	m.floor = s
	d, _ := hex.DecodeString(s.Digest)
	copy(m.digest[:], d)
	ks, err := protocol.VerifyKeySet(s.Token, m.cfg.Roots, s.Version, m.digest)
	if err == nil && (ks.Version != s.Version || ks.Digest != m.digest) {
		err = errors.New("token does not match its record")
	}
	if err != nil {
		m.log.Warn("stored key set does not verify; waiting for a new one", "error", err)
		return
	}
	m.ks = ks
}

func parseStored(b []byte) (stored, error) {
	var s stored
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("%s: malformed", StateFile)
	}
	d, err := hex.DecodeString(s.Digest)
	if s.Schema != 1 || s.Version < 1 || err != nil || len(d) != sha256.Size || s.VerifiedAt.IsZero() {
		return s, fmt.Errorf("%s: invalid", StateFile)
	}
	return s, nil
}

// Offer verifies a key set fetched through TUF. A refused offer changes
// nothing.
func (m *Manager) Offer(token []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, err := protocol.VerifyKeySet(string(token), m.cfg.Roots, m.floor.Version, m.digest)
	if err != nil {
		m.log.Warn("key set refused", "error", err)
		return err
	}
	verified := m.cfg.Now().UTC()
	if verified.Before(m.floor.VerifiedAt) {
		verified = m.floor.VerifiedAt
	}
	s := stored{Schema: 1, Token: string(token), Version: ks.Version, Digest: hex.EncodeToString(ks.Digest[:]),
		VerifiedAt: verified}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(filepath.Join(m.cfg.Dir, StateFile), b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return err
	}
	if m.ks == nil || m.ks.Version != ks.Version {
		m.log.Info("key set accepted", "version", ks.Version)
	}
	m.ks, m.floor, m.digest = ks, s, ks.Digest
	return nil
}

// Current is the last verified key set, or nil.
func (m *Manager) Current() *protocol.KeySet {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ks
}

// TokenSHA256 is the SHA-256 (hex) of the accepted token as fetched, or "".
func (m *Manager) TokenSHA256() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ks == nil {
		return ""
	}
	s := sha256.Sum256([]byte(m.floor.Token))
	return hex.EncodeToString(s[:])
}

// Hold is why no new session may be dialled, or "".
func (m *Manager) Hold() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hold()
}

func (m *Manager) hold() string {
	if m.ks == nil {
		return HoldMissing
	}
	return ""
}

// Status describes the current key set.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Hold: m.hold()}
	if m.ks != nil {
		s.Version, s.Digest, s.VerifiedAt = m.ks.Version, m.floor.Digest, m.floor.VerifiedAt
	}
	return s
}
