package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// MigrateLegacy converts a pre-split config.json into machine.json +
// account.json. Idempotent: running twice is a no-op.
//
// Order of operations is chosen so a crash mid-migration leaves the client
// in a usable state:
//
//  1. If machine.json already exists, migration is done — return.
//  2. Read legacy config.json. If absent, fresh install — write an empty
//     machine.json and return. No account.json is created.
//  3. Generate machine_id, write machine.json with empty services list.
//  4. Write account.json from the legacy fields.
//  5. Delete legacy config.json.
//
// Steps 3-5 happen only after the prior step succeeded. A crash between 3
// and 4 means the client is unpaired (no account.json) but has a machine
// identity; the next run sees machine.json exists and skips migration.
// A crash between 4 and 5 leaves both new files plus the legacy file,
// which the next run also detects and cleans up.
//
// Service definitions are not populated here. Phase 3 of SEA-136 wires
// services into machine.json as the user adds them and as pair flows
// register them.
func MigrateLegacy() error {
	if MachineExists() {
		// Already migrated. Best-effort cleanup of any stale legacy file.
		if _, err := os.Stat(LegacyConfigPath()); err == nil {
			_ = os.Remove(LegacyConfigPath())
		}
		return nil
	}

	legacy, err := loadLegacyConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Fresh install. Write empty machine.json so future runs skip
			// this path.
			return seedFreshMachine()
		}
		return fmt.Errorf("read legacy config: %w", err)
	}

	machineID, err := GenerateMachineID()
	if err != nil {
		return fmt.Errorf("generate machine id: %w", err)
	}

	m := &Machine{
		MachineID:   machineID,
		MachineName: legacy.ServerName,
		Services:    []LocalService{},
	}
	if err := m.Save(); err != nil {
		return fmt.Errorf("save machine: %w", err)
	}

	a := &Account{
		ServerID:      legacy.ServerID,
		ServerName:    legacy.ServerName,
		FRPToken:      legacy.FRPToken,
		FRPServerAddr: legacy.FRPServerAddr,
		FRPServerPort: legacy.FRPServerPort,
		FRPUseTLS:     legacy.FRPUseTLS,
		APIURL:        legacy.APIURL,
		UserID:        legacy.UserID,
		UserEmail:     legacy.UserEmail,
	}
	if err := a.Save(); err != nil {
		return fmt.Errorf("save account: %w", err)
	}

	if err := os.Remove(LegacyConfigPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove legacy config: %w", err)
	}
	return nil
}

func loadLegacyConfig() (*Config, error) {
	data, err := os.ReadFile(LegacyConfigPath())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse legacy config: %w", err)
	}
	return &c, nil
}

func seedFreshMachine() error {
	id, err := GenerateMachineID()
	if err != nil {
		return fmt.Errorf("generate machine id: %w", err)
	}
	m := &Machine{MachineID: id, Services: []LocalService{}}
	if err := m.Save(); err != nil {
		return fmt.Errorf("save machine: %w", err)
	}
	return nil
}
