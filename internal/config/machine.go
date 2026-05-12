package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seawise/client/internal/paths"
)

// LocalService is a user-configured service definition that lives on the
// machine independently of any account binding. ServerServiceID and Subdomain
// are populated once the service is registered on the currently-paired
// account, and cleared on unpair.
type LocalService struct {
	LocalID         string `json:"local_id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	IconURL         string `json:"icon_url,omitempty"`
	ServerServiceID string `json:"server_service_id,omitempty"`
	Subdomain       string `json:"subdomain,omitempty"`
}

// Machine is the persistent, account-independent layer of client state.
// It survives pair/unpair and represents the physical machine the user
// configured.
type Machine struct {
	MachineID   string         `json:"machine_id"`
	MachineName string         `json:"machine_name,omitempty"`
	Services    []LocalService `json:"services"`
}

func MachinePath() string {
	return filepath.Join(paths.DataDir(), "machine.json")
}

func MachineExists() bool {
	_, err := os.Stat(MachinePath())
	return err == nil
}

// LoadMachine reads machine.json from disk.
func LoadMachine() (*Machine, error) {
	data, err := os.ReadFile(MachinePath())
	if err != nil {
		return nil, fmt.Errorf("read machine file: %w", err)
	}
	var m Machine
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse machine file: %w", err)
	}
	if m.Services == nil {
		m.Services = []LocalService{}
	}
	return &m, nil
}

// Save atomically and durably writes machine.json with 0600 permissions.
// Uses writeAtomic so a crash or power loss between write and disk flush
// does not leave a truncated file: machine_id is the stable identity the
// server uses to recognize re-pair events.
func (m *Machine) Save() error {
	if m.MachineID == "" {
		return errors.New("machine_id is required")
	}
	if m.Services == nil {
		m.Services = []LocalService{}
	}

	machinePath := MachinePath()
	if err := os.MkdirAll(filepath.Dir(machinePath), 0700); err != nil {
		return fmt.Errorf("create machine directory: %w", err)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal machine: %w", err)
	}

	if err := writeAtomic(machinePath, data, 0600); err != nil {
		return fmt.Errorf("write machine file: %w", err)
	}
	return nil
}

// GenerateMachineID returns a fresh 128-bit hex ID. Not a secret; purely
// a stable identifier the server can use to recognize re-pair events.
func GenerateMachineID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate machine id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateLocalID returns a fresh client-generated ID for a service entry.
func GenerateLocalID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate local id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
