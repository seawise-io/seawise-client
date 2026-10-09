// Package store keeps client v2 state under <datadir>/v2. It never writes
// outside that directory; v1 state is only read, through internal/legacy.
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/seawise/client/internal/legacy"
)

const (
	SchemaVersion = 1
	SubDir        = "v2"
	StateFile     = "state.json"
	SecretsFile   = "secrets.json"
	MaxTargets    = legacy.MaxServices

	SourceV1Machine = "v1-machine"
	SourceV1FRPC    = "v1-frpc"
	SourceLocal     = "local"
)

var (
	ErrNewerSchema = errors.New("state was written by a newer client")
	ErrUnsafePath  = errors.New("unsafe store path")
	ErrInvalid     = errors.New("invalid state")
)

type Account struct {
	ServerID      string `json:"server_id"`
	ServerName    string `json:"server_name,omitempty"`
	FRPServerAddr string `json:"frp_server_addr"`
	FRPServerPort int    `json:"frp_server_port"`
	FRPUseTLS     bool   `json:"frp_use_tls"`
	APIURL        string `json:"api_url"`
	UserID        string `json:"user_id,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
}

type Target struct {
	LocalID         string     `json:"local_id"`
	Name            string     `json:"name"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	IconURL         string     `json:"icon_url,omitempty"`
	ServerServiceID string     `json:"server_service_id,omitempty"`
	Subdomain       string     `json:"subdomain,omitempty"`
	Disabled        bool       `json:"disabled,omitempty"`
	Source          string     `json:"source"`
	Grandfathered   bool       `json:"grandfathered,omitempty"`
	ConfirmedAt     *time.Time `json:"confirmed_at,omitempty"`
	// Allowed lists the target classes the owner confirmed locally, beyond
	// private addresses. Grandfathered targets are not limited by it.
	Allowed []string `json:"allowed,omitempty"`
}

// Grants a target can hold; see internal/targetpolicy.
var KnownGrants = map[string]bool{"public": true, "loopback": true, "sensitive": true, "smtp": true}

type ImportedFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Import struct {
	Layout        string         `json:"layout"`
	AccountSource string         `json:"account_source,omitempty"`
	Files         []ImportedFile `json:"files"`
	Warnings      []string       `json:"warnings,omitempty"`
}

type State struct {
	Schema      int        `json:"schema"`
	CreatedAt   time.Time  `json:"created_at"`
	UpgradedAt  *time.Time `json:"upgraded_at,omitempty"`
	Import      *Import    `json:"import,omitempty"`
	MachineID   string     `json:"machine_id"`
	MachineName string     `json:"machine_name,omitempty"`
	Account     *Account   `json:"account,omitempty"`
	Targets     []Target   `json:"targets"`
}

type Secrets struct {
	Schema            int    `json:"schema"`
	FRPToken          string `json:"frp_token,omitempty"`
	AdminPasswordHash string `json:"admin_password_hash,omitempty"`
}

type Store struct {
	dir      string
	mu       sync.Mutex
	state    State
	secrets  Secrets
	Warnings []string
}

// currentSchema is a variable so tests can exercise migrations.
var currentSchema = SchemaVersion

// migrations[i] upgrades a raw state document from schema i+1 to i+2.
var migrations []func(doc map[string]any) error

// Open loads <dataDir>/v2, importing v1 state on first run.
func Open(dataDir string, now func() time.Time) (*Store, error) {
	dir := filepath.Join(dataDir, SubDir)
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case !info.IsDir():
		return nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, dir)
	}

	s := &Store{dir: dir}
	if err == nil {
		if err := removeStaleTemps(dir); err != nil {
			return nil, fmt.Errorf("clean temp files: %w", err)
		}
		loaded, err := s.load()
		if err != nil {
			return nil, err
		}
		if loaded {
			return s, nil
		}
	}
	if err := s.importV1(dataDir, now().UTC()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneState(s.state)
}

func (s *Store) Secrets() Secrets {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets
}

// Update applies fn to a copy of the state and persists it. The in-memory
// state changes only if the new file is in place.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	next.Schema = currentSchema
	if err := validateState(&next); err != nil {
		return err
	}
	err := writeJSON(filepath.Join(s.dir, StateFile), next)
	if err != nil && !errors.Is(err, ErrNotDurable) {
		return err
	}
	s.state = next
	return err
}

func (s *Store) UpdateSecrets(fn func(*Secrets) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.secrets
	if err := fn(&next); err != nil {
		return err
	}
	next.Schema = currentSchema
	err := writeJSON(filepath.Join(s.dir, SecretsFile), next)
	if err != nil && !errors.Is(err, ErrNotDurable) {
		return err
	}
	s.secrets = next
	return err
}

func (s *Store) load() (bool, error) {
	statePath := filepath.Join(s.dir, StateFile)
	if err := checkRegular(statePath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return false, err
	}
	state, migrated, err := decodeState(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %w", StateFile, err)
	}

	secretsPath := filepath.Join(s.dir, SecretsFile)
	var secrets Secrets
	switch err := checkRegular(secretsPath); {
	case errors.Is(err, fs.ErrNotExist):
		secrets.Schema = currentSchema
	case err != nil:
		return false, err
	default:
		info, err := os.Stat(secretsPath)
		if err != nil {
			return false, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(secretsPath, 0o600); err != nil {
				return false, err
			}
			s.Warnings = append(s.Warnings, fmt.Sprintf("%s permissions tightened from %v", SecretsFile, info.Mode().Perm()))
		}
		b, err := os.ReadFile(secretsPath)
		if err != nil {
			return false, err
		}
		if err := strictUnmarshal(b, &secrets); err != nil {
			return false, fmt.Errorf("%s: %w", SecretsFile, err)
		}
		if secrets.Schema > currentSchema {
			return false, fmt.Errorf("%s: %w", SecretsFile, ErrNewerSchema)
		}
	}

	if migrated {
		if err := writeJSON(statePath, state); err != nil && !errors.Is(err, ErrNotDurable) {
			return false, err
		}
	}
	s.state, s.secrets = state, secrets
	return true, nil
}

func decodeState(raw []byte) (State, bool, error) {
	var doc map[string]any
	if err := strictUnmarshal(raw, &doc); err != nil {
		return State{}, false, err
	}
	v, ok := doc["schema"].(float64)
	if !ok || v < 1 || v != float64(int(v)) {
		return State{}, false, fmt.Errorf("%w: missing schema", ErrInvalid)
	}
	version := int(v)
	if version > currentSchema {
		return State{}, false, ErrNewerSchema
	}
	migrated := false
	for version < currentSchema {
		if version-1 >= len(migrations) {
			return State{}, false, fmt.Errorf("%w: no migration from schema %d", ErrInvalid, version)
		}
		if err := migrations[version-1](doc); err != nil {
			return State{}, false, fmt.Errorf("migrate schema %d: %w", version, err)
		}
		version++
		doc["schema"] = version
		migrated = true
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return State{}, false, err
	}
	var st State
	if err := strictUnmarshal(b, &st); err != nil {
		return State{}, false, err
	}
	if err := validateState(&st); err != nil {
		return State{}, false, err
	}
	return st, migrated, nil
}

func (s *Store) importV1(dataDir string, now time.Time) error {
	snap, err := legacy.Read(dataDir)
	if err != nil {
		return fmt.Errorf("read v1 state: %w", err)
	}

	st := State{Schema: currentSchema, CreatedAt: now, MachineID: snap.MachineID, MachineName: snap.MachineName, Targets: []Target{}}
	if st.MachineID == "" {
		if st.MachineID, err = randomID(); err != nil {
			return err
		}
	}
	found := len(snap.Files) > 0
	if found {
		t := now
		st.UpgradedAt = &t
		imp := &Import{Layout: string(snap.Layout), AccountSource: snap.AccountSource, Files: []ImportedFile{}, Warnings: snap.Warnings}
		for _, f := range snap.Files {
			imp.Files = append(imp.Files, ImportedFile{Name: f.Name, Size: f.Size, SHA256: f.SHA256})
		}
		st.Import = imp
	}
	sec := Secrets{Schema: currentSchema, AdminPasswordHash: string(snap.PasswordHash)}
	if a := snap.Account; a != nil {
		st.Account = &Account{ServerID: a.ServerID, ServerName: a.ServerName, FRPServerAddr: a.FRPServerAddr, FRPServerPort: a.FRPServerPort, FRPUseTLS: a.FRPUseTLS, APIURL: a.APIURL, UserID: a.UserID, UserEmail: a.UserEmail}
		sec.FRPToken = a.FRPToken
	}
	if st.Targets, err = grandfatheredTargets(snap, now); err != nil {
		return err
	}
	if err := validateState(&st); err != nil {
		return fmt.Errorf("imported state: %w", err)
	}

	if err := os.Mkdir(s.dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := checkDir(s.dir); err != nil {
		return err
	}
	// secrets first: state.json marks the import as complete.
	if err := writeJSON(filepath.Join(s.dir, SecretsFile), sec); err != nil && !errors.Is(err, ErrNotDurable) {
		return err
	}
	if err := writeJSON(filepath.Join(s.dir, StateFile), st); err != nil && !errors.Is(err, ErrNotDurable) {
		return err
	}
	s.state, s.secrets = st, sec
	return nil
}

func grandfatheredTargets(snap *legacy.Snapshot, now time.Time) ([]Target, error) {
	confirmed := now
	out := []Target{}
	seenAddr := map[string]bool{}
	seenSub := map[string]bool{}
	for _, svc := range snap.Services {
		out = append(out, Target{
			LocalID: svc.LocalID, Name: svc.Name, Host: svc.Host, Port: svc.Port, IconURL: svc.IconURL,
			ServerServiceID: svc.ServerServiceID, Subdomain: svc.Subdomain, Disabled: svc.Disabled,
			Source: SourceV1Machine, Grandfathered: true, ConfirmedAt: &confirmed,
		})
		seenAddr[net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))] = true
		if svc.Subdomain != "" {
			seenSub[svc.Subdomain] = true
		}
	}
	if snap.FRPC != nil {
		for _, p := range snap.FRPC.Proxies {
			addr := net.JoinHostPort(p.LocalIP, strconv.Itoa(p.LocalPort))
			if p.LocalIP == "" || p.LocalPort < 1 || seenAddr[addr] || (p.Subdomain != "" && seenSub[p.Subdomain]) {
				continue
			}
			if len(out) >= MaxTargets {
				break
			}
			id, err := randomID()
			if err != nil {
				return nil, err
			}
			out = append(out, Target{
				LocalID: id, Name: p.Name, Host: p.LocalIP, Port: p.LocalPort, Subdomain: p.Subdomain,
				Source: SourceV1FRPC, Grandfathered: true, ConfirmedAt: &confirmed,
			})
			seenAddr[addr] = true
			if p.Subdomain != "" {
				seenSub[p.Subdomain] = true
			}
		}
	}
	return out, nil
}

func validateState(st *State) error {
	if st.Schema != currentSchema {
		return fmt.Errorf("%w: schema %d", ErrInvalid, st.Schema)
	}
	if st.MachineID == "" {
		return fmt.Errorf("%w: machine_id required", ErrInvalid)
	}
	if st.Targets == nil {
		st.Targets = []Target{}
	}
	if len(st.Targets) > MaxTargets {
		return fmt.Errorf("%w: too many targets", ErrInvalid)
	}
	ids := map[string]bool{}
	for i, t := range st.Targets {
		switch {
		case t.LocalID == "" || ids[t.LocalID]:
			return fmt.Errorf("%w: target %d: missing or duplicate local_id", ErrInvalid, i)
		case t.Host == "":
			return fmt.Errorf("%w: target %d: host required", ErrInvalid, i)
		case t.Port < 1 || t.Port > 65535:
			return fmt.Errorf("%w: target %d: port out of range", ErrInvalid, i)
		case t.Source != SourceV1Machine && t.Source != SourceV1FRPC && t.Source != SourceLocal:
			return fmt.Errorf("%w: target %d: unknown source", ErrInvalid, i)
		}
		seen := map[string]bool{}
		for _, g := range t.Allowed {
			if !KnownGrants[g] || seen[g] {
				return fmt.Errorf("%w: target %d: unknown or repeated grant", ErrInvalid, i)
			}
			seen[g] = true
		}
		ids[t.LocalID] = true
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, append(b, '\n'), 0o600)
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}

func checkRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	return nil
}

func checkDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafePath, path)
	}
	return nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func cloneState(st State) State {
	out := st
	out.Targets = append([]Target(nil), st.Targets...)
	if out.Targets == nil {
		out.Targets = []Target{}
	}
	if st.Account != nil {
		a := *st.Account
		out.Account = &a
	}
	if st.UpgradedAt != nil {
		t := *st.UpgradedAt
		out.UpgradedAt = &t
	}
	if st.Import != nil {
		imp := *st.Import
		imp.Files = append([]ImportedFile(nil), st.Import.Files...)
		imp.Warnings = append([]string(nil), st.Import.Warnings...)
		out.Import = &imp
	}
	for i := range out.Targets {
		if c := out.Targets[i].ConfirmedAt; c != nil {
			t := *c
			out.Targets[i].ConfirmedAt = &t
		}
		out.Targets[i].Allowed = append([]string(nil), out.Targets[i].Allowed...)
	}
	return out
}
