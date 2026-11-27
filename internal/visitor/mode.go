package visitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/seawise/client/internal/store"
)

// ModeFile holds the enforcement mode set by signed instruction.
const ModeFile = "enforcement.json"

type modeFile struct {
	Schema int   `json:"schema"`
	Mode   Mode  `json:"mode"`
	Seq    int64 `json:"seq"`
}

// ModeStatus is the stored mode, the seq of the instruction that set it (0
// for never) and why the file could not be used, if so.
type ModeStatus struct {
	Mode  Mode   `json:"mode"`
	Seq   int64  `json:"seq,omitempty"`
	Error string `json:"error,omitempty"`
}

// ModeStore keeps one server's enforcement mode. A missing or unusable file
// is Observe; only Set, called for a verified instruction, changes it.
type ModeStore struct {
	path string
	mu   sync.RWMutex
	cur  ModeStatus
}

// OpenMode opens the mode of the server whose folder is dir, creating the
// folder (0700) if needed.
func OpenMode(dir string, log *slog.Logger) (*ModeStore, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := store.CheckDir(dir); err != nil {
		return nil, err
	}
	m := &ModeStore{path: filepath.Join(dir, ModeFile), cur: ModeStatus{Mode: Observe}}
	b, err := store.ReadOwned(m.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return m, nil
	case err == nil:
		var f modeFile
		if f, err = parseMode(b); err == nil {
			m.cur = ModeStatus{Mode: f.Mode, Seq: f.Seq}
			return m, nil
		}
	}
	m.cur.Error = "unreadable"
	log.Warn("visitor-token mode file unusable; visitors are observed until SeaWise sets the mode again", "error", err)
	return m, nil
}

func parseMode(b []byte) (modeFile, error) {
	var f modeFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, errors.New("malformed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return f, errors.New("trailing data")
	}
	if f.Schema != 1 || !f.Mode.known() || f.Seq < 0 {
		return f, errors.New("invalid")
	}
	return f, nil
}

func (m Mode) known() bool { return m == Observe || m == Enforce }

// Seq is the seq of the instruction that set the mode, 0 for none.
func (s *ModeStore) Seq() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur.Seq
}

// Mode is the current mode.
func (s *ModeStore) Mode() Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur.Mode
}

// Status is the current mode and its origin.
func (s *ModeStore) Status() ModeStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Set stores mode for the instruction with seq. A seq at or below the
// stored one changes nothing. The mode changes in memory only once it is
// written.
func (s *ModeStore) Set(mode Mode, seq int64) (bool, error) {
	if !mode.known() || seq < 1 {
		return false, fmt.Errorf("invalid visitor-token mode %q seq %d", mode, seq)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.cur.Seq {
		return false, nil
	}
	b, err := json.Marshal(modeFile{Schema: 1, Mode: mode, Seq: seq})
	if err != nil {
		return false, err
	}
	if err := store.WriteFileAtomic(s.path, b, 0o600); err != nil && !errors.Is(err, store.ErrNotDurable) {
		return false, err
	}
	s.cur = ModeStatus{Mode: mode, Seq: seq}
	return true, nil
}
