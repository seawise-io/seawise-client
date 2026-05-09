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
//  1. If machine.json AND account.json both exist, migration is done —
//     clean up any stale legacy file and return. The "AND account.json"
//     guard preserves the legacy file when a previous run crashed between
//     step 3 and step 4 (machine.json saved, account.json save failed):
//     the legacy file is the only remaining record of the user's account
//     binding in that state, so deleting it would strand the user
//     permanently unpaired.
//  2. If only machine.json exists (partial migration), leave the legacy
//     file alone so the user can recover and try again on next start.
//  3. Read legacy config.json. If absent, fresh install — write an empty
//     machine.json and return. No account.json is created.
//  4. Generate machine_id, write machine.json with empty services list.
//  5. Write account.json from the legacy fields.
//  6. Delete legacy config.json.
//
// Steps 4-6 happen only after the prior step succeeded.
//
// Service definitions are not populated here. Phase 3 of SEA-136 wires
// services into machine.json as the user adds them and as pair flows
// register them.
func MigrateLegacy() error {
	if MachineExists() {
		// Only clean up legacy when migration is GENUINELY complete (both
		// new files exist). On partial-migration state (machine.json but
		// no account.json) the legacy file is preserved as a recovery
		// record — the user can either delete it manually or the next
		// successful pair flow will rewrite both files.
		if AccountExists() {
			if _, err := os.Stat(LegacyConfigPath()); err == nil {
				_ = os.Remove(LegacyConfigPath())
			}
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
