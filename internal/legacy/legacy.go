// Package legacy reads the state files of a v1 client data directory.
//
// It only ever opens files read-only and never follows symlinks, so a v1
// binary started on the same directory later finds its files unchanged.
package legacy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	MaxFileSize = 1 << 20
	MaxServices = 1000
)

var (
	ErrNotRegular = errors.New("not a regular file")
	ErrTooLarge   = errors.New("file too large")
	ErrMalformed  = errors.New("malformed file")
)

const (
	fileAccount  = "account.json"
	fileConfig   = "config.json"
	fileMachine  = "machine.json"
	filePassword = "password.hash"
	fileFRPC     = "frpc.toml"
)

type Layout string

const (
	LayoutEmpty   Layout = "empty"
	LayoutSingle  Layout = "single"
	LayoutSplit   Layout = "split"
	LayoutPartial Layout = "partial"
)

type Account struct {
	ServerID      string `json:"server_id"`
	ServerName    string `json:"server_name"`
	FRPToken      string `json:"frp_token"`
	FRPServerAddr string `json:"frp_server_addr"`
	FRPServerPort int    `json:"frp_server_port"`
	FRPUseTLS     bool   `json:"frp_use_tls"`
	APIURL        string `json:"api_url"`
	UserID        string `json:"user_id"`
	UserEmail     string `json:"user_email"`
}

type Service struct {
	LocalID         string `json:"local_id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	IconURL         string `json:"icon_url,omitempty"`
	ServerServiceID string `json:"server_service_id,omitempty"`
	Subdomain       string `json:"subdomain,omitempty"`
	Disabled        bool   `json:"disabled,omitempty"`
}

type Machine struct {
	MachineID   string    `json:"machine_id"`
	MachineName string    `json:"machine_name"`
	Services    []Service `json:"services"`
}

type File struct {
	Name   string
	Size   int64
	SHA256 string
}

type Snapshot struct {
	Layout        Layout
	Account       *Account
	AccountSource string
	MachineID     string
	MachineName   string
	Services      []Service
	PasswordHash  []byte
	FRPC          *FRPCConfig
	Files         []File
	Warnings      []string
}

// Read loads the v1 state in dataDir without modifying anything.
func Read(dataDir string) (*Snapshot, error) {
	info, err := os.Stat(dataDir)
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("data dir %s: not a directory", dataDir)
	}

	s := &Snapshot{Layout: LayoutEmpty}
	r := reader{dir: dataDir, snap: s}

	accountData, hasAccount, err := r.read(fileAccount)
	if err != nil {
		return nil, err
	}
	machineData, hasMachine, err := r.read(fileMachine)
	if err != nil {
		return nil, err
	}

	switch {
	case hasAccount:
		s.Layout = LayoutSplit
		a, err := parseAccount(accountData)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fileAccount, err)
		}
		s.Account, s.AccountSource = a, fileAccount
	case hasMachine:
		s.Layout = LayoutSplit
		exists, err := r.exists(fileConfig)
		if err != nil {
			return nil, err
		}
		if exists {
			s.Layout = LayoutPartial
			s.warn("config.json present without account.json; treated as unpaired")
		}
	default:
		configData, hasConfig, err := r.read(fileConfig)
		if err != nil {
			return nil, err
		}
		if hasConfig {
			s.Layout = LayoutSingle
			a, err := parseAccount(configData)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", fileConfig, err)
			}
			s.Account, s.AccountSource = a, fileConfig
		}
	}

	if hasMachine {
		m, err := parseMachine(machineData, &s.Warnings)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fileMachine, err)
		}
		s.MachineID, s.MachineName, s.Services = m.MachineID, m.MachineName, m.Services
	}

	pw, hasPassword, err := r.read(filePassword)
	if err != nil {
		return nil, err
	}
	if hasPassword {
		if !isBcrypt(pw) {
			return nil, fmt.Errorf("%s: %w: not a bcrypt hash", filePassword, ErrMalformed)
		}
		s.PasswordHash = pw
	}

	frpcData, hasFRPC, err := r.read(fileFRPC)
	switch {
	case err != nil:
		s.warn(fmt.Sprintf("frpc.toml skipped: %v", err))
	case hasFRPC:
		cfg, err := parseFRPC(frpcData)
		if err != nil {
			s.warn(fmt.Sprintf("frpc.toml skipped: %v", err))
		} else {
			s.FRPC = cfg
		}
	}
	return s, nil
}

func (s *Snapshot) warn(msg string) {
	s.Warnings = append(s.Warnings, msg)
}

type reader struct {
	dir  string
	snap *Snapshot
}

func (r reader) exists(name string) (bool, error) {
	_, err := os.Lstat(filepath.Join(r.dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return true, nil
}

// read returns the file contents, or ok=false when the file does not exist.
func (r reader) read(name string) (data []byte, ok bool, err error) {
	path := filepath.Join(r.dir, name)
	before, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if !before.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s: %w", name, ErrNotRegular)
	}
	if before.Size() > MaxFileSize {
		return nil, false, fmt.Errorf("%s: %w", name, ErrTooLarge)
	}

	f, err := os.OpenFile(path, readOnlyFlags, 0)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	defer f.Close()

	opened, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, false, fmt.Errorf("%s: %w", name, ErrNotRegular)
	}

	data, err = io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > MaxFileSize {
		return nil, false, fmt.Errorf("%s: %w", name, ErrTooLarge)
	}

	sum := sha256.Sum256(data)
	r.snap.Files = append(r.snap.Files, File{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
	return data, true, nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: malformed JSON at offset %d", ErrMalformed, jsonOffset(err, dec))
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: malformed JSON at offset %d: trailing data", ErrMalformed, dec.InputOffset())
	}
	return nil
}

// jsonOffset locates a decode error without quoting the input, which may
// hold secrets.
func jsonOffset(err error, dec *json.Decoder) int64 {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return syn.Offset
	case errors.As(err, &typ):
		return typ.Offset
	}
	return dec.InputOffset()
}

func parseAccount(data []byte) (*Account, error) {
	var a Account
	if err := decodeStrict(data, &a); err != nil {
		return nil, err
	}
	if a.ServerID == "" || a.FRPToken == "" {
		return nil, fmt.Errorf("%w: server_id and frp_token are required", ErrMalformed)
	}
	return &a, nil
}

const (
	maxIDLen   = 128
	maxNameLen = 256
	maxHostLen = 253
	maxURLLen  = 2048
)

func parseMachine(data []byte, warnings *[]string) (*Machine, error) {
	var raw struct {
		MachineID   string            `json:"machine_id"`
		MachineName string            `json:"machine_name"`
		Services    []json.RawMessage `json:"services"`
	}
	if err := decodeStrict(data, &raw); err != nil {
		return nil, err
	}
	if len(raw.Services) > MaxServices {
		return nil, fmt.Errorf("%w: more than %d services", ErrMalformed, MaxServices)
	}
	m := &Machine{MachineID: raw.MachineID, MachineName: raw.MachineName, Services: []Service{}}
	seen := map[string]bool{}
	for i, item := range raw.Services {
		var svc Service
		if err := decodeStrict(item, &svc); err != nil {
			*warnings = append(*warnings, fmt.Sprintf("service %d skipped: unreadable", i))
			continue
		}
		if reason := invalidService(svc, seen); reason != "" {
			*warnings = append(*warnings, fmt.Sprintf("service %d skipped: %s", i, reason))
			continue
		}
		seen[svc.LocalID] = true
		m.Services = append(m.Services, svc)
	}
	return m, nil
}

func invalidService(s Service, seen map[string]bool) string {
	switch {
	case s.LocalID == "" || len(s.LocalID) > maxIDLen:
		return "bad local_id"
	case seen[s.LocalID]:
		return "duplicate local_id"
	case s.Host == "" || len(s.Host) > maxHostLen:
		return "bad host"
	case s.Port < 1 || s.Port > 65535:
		return "bad port"
	case len(s.Name) > maxNameLen || len(s.Subdomain) > maxHostLen || len(s.ServerServiceID) > maxIDLen || len(s.IconURL) > maxURLLen:
		return "field too long"
	}
	return ""
}

func isBcrypt(b []byte) bool {
	if len(b) != 60 || b[0] != '$' || b[1] != '2' || b[3] != '$' || b[6] != '$' {
		return false
	}
	switch b[2] {
	case 'a', 'b', 'y':
	default:
		return false
	}
	for _, c := range b[7:] {
		if !(c == '.' || c == '/' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return b[4] >= '0' && b[4] <= '3' && b[5] >= '0' && b[5] <= '9'
}
