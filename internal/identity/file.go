package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/seawise/client/internal/store"
)

// KeyFile is the file backend's file in the v2 state directory.
const KeyFile = "device_key.json"

const (
	fileSchema  = 1
	maxFileSize = 16 << 10
)

// FileKeystore keeps the device key in a 0600 file in the agent's v2 state
// directory. The file is opened without following symlinks, must be owned
// by this user with no group or other access, and is replaced atomically.
// The caller holds the store lock, so one agent uses the file at a time.
type FileKeystore struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	current *Key
	pending *Key
	closed  bool
}

type fileRecord struct {
	Seed      []byte    `json:"seed"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

type fileDoc struct {
	Schema  int         `json:"schema"`
	Current *fileRecord `json:"current"`
	Pending *fileRecord `json:"pending,omitempty"`
}

// OpenFile loads the key file in dir, if there is one.
func OpenFile(dir string, now func() time.Time) (*FileKeystore, error) {
	if err := store.CheckDir(dir); err != nil {
		return nil, err
	}
	ks := &FileKeystore{path: filepath.Join(dir, KeyFile), now: now}
	if err := ks.load(); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *FileKeystore) Backend() string { return BackendFile }

func (ks *FileKeystore) load() error {
	f, err := store.OpenOwned(ks.path, os.O_RDONLY)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	defer clear(b)
	if err != nil {
		return err
	}
	if len(b) > maxFileSize {
		return fmt.Errorf("%w: %s too large", ErrCorrupt, KeyFile)
	}
	var doc fileDoc
	defer clearDoc(&doc)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: %s does not parse", ErrCorrupt, KeyFile)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data in %s", ErrCorrupt, KeyFile)
	}
	if doc.Schema > fileSchema {
		return fmt.Errorf("%s: %w", KeyFile, store.ErrNewerSchema)
	}
	if doc.Schema != fileSchema || doc.Current == nil {
		return fmt.Errorf("%w: %s has no current key", ErrCorrupt, KeyFile)
	}
	cur, err := recordKey(doc.Current)
	if err != nil {
		return err
	}
	var pend *Key
	if doc.Pending != nil {
		if pend, err = recordKey(doc.Pending); err != nil {
			cur.destroy()
			return err
		}
		if pend.PublicKey().Equal(cur.PublicKey()) {
			cur.destroy()
			pend.destroy()
			return fmt.Errorf("%w: pending key equals current key", ErrCorrupt)
		}
	}
	ks.current, ks.pending = cur, pend
	return nil
}

func recordKey(r *fileRecord) (*Key, error) {
	k, err := keyFromSeed(r.Seed, r.CreatedAt)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(k.d.pub) != r.PublicKey {
		k.destroy()
		return nil, fmt.Errorf("%w: public key does not match the private key", ErrCorrupt)
	}
	return k, nil
}

func clearDoc(doc *fileDoc) {
	for _, r := range []*fileRecord{doc.Current, doc.Pending} {
		if r != nil {
			clear(r.Seed)
		}
	}
}

func toRecord(k *Key) (*fileRecord, error) {
	seed, err := k.seed()
	if err != nil {
		return nil, err
	}
	return &fileRecord{Seed: seed, PublicKey: base64.RawURLEncoding.EncodeToString(k.d.pub), CreatedAt: k.d.createdAt}, nil
}

// persist writes cur and pend. A store.ErrNotDurable result means the file
// is in place but the directory sync failed; callers treat it as written.
func (ks *FileKeystore) persist(cur, pend *Key) error {
	doc := fileDoc{Schema: fileSchema}
	defer clearDoc(&doc)
	var err error
	if doc.Current, err = toRecord(cur); err != nil {
		return err
	}
	if pend != nil {
		if doc.Pending, err = toRecord(pend); err != nil {
			return err
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer clear(b)
	return store.WriteFileAtomic(ks.path, b, 0o600)
}

func written(err error) bool { return err == nil || errors.Is(err, store.ErrNotDurable) }

func (ks *FileKeystore) Current() (*Key, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	switch {
	case ks.closed:
		return nil, ErrClosed
	case ks.current == nil:
		return nil, ErrNoKey
	}
	return ks.current, nil
}

func (ks *FileKeystore) Pending() (*Key, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	switch {
	case ks.closed:
		return nil, ErrClosed
	case ks.pending == nil:
		return nil, ErrNoKey
	}
	return ks.pending, nil
}

func (ks *FileKeystore) Create() (*Key, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	switch {
	case ks.closed:
		return nil, ErrClosed
	case ks.current != nil:
		return nil, ErrKeyExists
	}
	k, err := generate(ks.now())
	if err != nil {
		return nil, err
	}
	err = ks.persist(k, nil)
	if !written(err) {
		k.destroy()
		return nil, err
	}
	ks.current = k
	return k, err
}

func (ks *FileKeystore) BeginRotation() (*Key, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	switch {
	case ks.closed:
		return nil, ErrClosed
	case ks.current == nil:
		return nil, ErrNoKey
	case ks.pending != nil:
		return ks.pending, nil
	}
	k, err := generate(ks.now())
	if err != nil {
		return nil, err
	}
	err = ks.persist(ks.current, k)
	if !written(err) {
		k.destroy()
		return nil, err
	}
	ks.pending = k
	return k, err
}

func (ks *FileKeystore) CommitRotation() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	switch {
	case ks.closed:
		return ErrClosed
	case ks.pending == nil:
		return ErrNoKey
	}
	err := ks.persist(ks.pending, nil)
	if !written(err) {
		return err
	}
	ks.current.destroy()
	ks.current, ks.pending = ks.pending, nil
	return err
}

func (ks *FileKeystore) AbortRotation() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	switch {
	case ks.closed:
		return ErrClosed
	case ks.pending == nil:
		return nil
	}
	err := ks.persist(ks.current, nil)
	if !written(err) {
		return err
	}
	ks.pending.destroy()
	ks.pending = nil
	return err
}

func (ks *FileKeystore) Close() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, k := range []*Key{ks.current, ks.pending} {
		if k != nil {
			k.destroy()
		}
	}
	ks.current, ks.pending, ks.closed = nil, nil, true
	return nil
}

var _ Keystore = (*FileKeystore)(nil)
