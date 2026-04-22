// Package config manages persistent client state.
//
// State is split into two layers:
//
//   - machine.json — the persistent, account-independent layer: machine_id
//     and user-configured service definitions. Survives pair/unpair.
//   - account.json — the ephemeral layer: server_id, FRP token, subdomains,
//     and the currently-connected user. Created on pair, deleted on unpair.
//
// The Config struct is a convenience view that combines both layers for
// existing callers. Going forward, new code should read Machine and Account
// directly.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/paths"
)

// Config is the legacy unified view of client state. Kept as a facade so
// existing callers do not need to change during the split. New code should
// prefer LoadMachine / LoadAccount directly.
type Config struct {
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

// LegacyConfigPath returns the path to the pre-split config.json. Used only
// by the migration routine.
func LegacyConfigPath() string {
	return filepath.Join(paths.DataDir(), "config.json")
}

// Exists reports whether the client is currently paired (has an account
// binding on disk).
func Exists() bool {
	return AccountExists()
}

// Load reads the current account binding and returns it as a Config for
// legacy callers. Returns an error if the client is not paired.
func Load() (*Config, error) {
	a, err := LoadAccount()
	if err != nil {
		return nil, err
	}
	return &Config{
		ServerID:      a.ServerID,
		ServerName:    a.ServerName,
		FRPToken:      a.FRPToken,
		FRPServerAddr: a.FRPServerAddr,
		FRPServerPort: a.FRPServerPort,
		FRPUseTLS:     a.FRPUseTLS,
		APIURL:        a.APIURL,
		UserID:        a.UserID,
		UserEmail:     a.UserEmail,
	}, nil
}

// Save persists the account binding. Also ensures machine.json exists so
// the two files are always in sync after a successful save.
func (c *Config) Save() error {
	if c == nil {
		return errors.New("nil config")
	}
	if !MachineExists() {
		id, err := GenerateMachineID()
		if err != nil {
			return fmt.Errorf("generate machine id: %w", err)
		}
		m := &Machine{MachineID: id, MachineName: c.ServerName, Services: []LocalService{}}
		if err := m.Save(); err != nil {
			return fmt.Errorf("save machine: %w", err)
		}
	}
	a := &Account{
		ServerID:      c.ServerID,
		ServerName:    c.ServerName,
		FRPToken:      c.FRPToken,
		FRPServerAddr: c.FRPServerAddr,
		FRPServerPort: c.FRPServerPort,
		FRPUseTLS:     c.FRPUseTLS,
		APIURL:        c.APIURL,
		UserID:        c.UserID,
		UserEmail:     c.UserEmail,
	}
	return a.Save()
}

// Delete removes both the account binding and any pre-split legacy config
// file. Machine state is preserved.
//
// NOTE: after phase 4 of SEA-136, this is the canonical "unpair" behavior.
// Prior to phase 4, existing callers still expect full wipe — that change
// will land in SEA-140.
func Delete() error {
	if err := DeleteAccount(); err != nil {
		return err
	}
	// Best-effort cleanup of any leftover legacy config. Ignore "not exist".
	if err := os.Remove(LegacyConfigPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete legacy config file: %w", err)
	}
	return nil
}

// GetAPIURL resolves the API URL from config, env var, or default.
func GetAPIURL(cfg *Config) string {
	if cfg != nil && cfg.APIURL != "" {
		return cfg.APIURL
	}
	if url := os.Getenv("SEAWISE_API_URL"); url != "" {
		return url
	}
	return constants.DefaultAPIURL
}

// GetWebURL resolves the web dashboard URL.
func GetWebURL() string {
	if url := os.Getenv("SEAWISE_WEB_URL"); url != "" {
		return url
	}
	return constants.DefaultWebURL
}
