package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seawise/client/internal/paths"
)

// Account is the ephemeral layer of client state: everything tied to the
// currently-paired SeaWise account. Created on pair, deleted on unpair.
type Account struct {
	ServerID      string `json:"server_id"`
	ServerName    string `json:"server_name,omitempty"`
	FRPToken      string `json:"frp_token"`
	FRPServerAddr string `json:"frp_server_addr"`
	FRPServerPort int    `json:"frp_server_port"`
	FRPUseTLS     bool   `json:"frp_use_tls"`
	APIURL        string `json:"api_url"`
	UserID        string `json:"user_id"`
	UserEmail     string `json:"user_email"`
}

func AccountPath() string {
	return filepath.Join(paths.DataDir(), "account.json")
}

func AccountExists() bool {
	_, err := os.Stat(AccountPath())
	return err == nil
}

// LoadAccount reads account.json from disk.
func LoadAccount() (*Account, error) {
	data, err := os.ReadFile(AccountPath())
	if err != nil {
		return nil, fmt.Errorf("read account file: %w", err)
	}
	var a Account
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parse account file: %w", err)
	}
	return &a, nil
}

// Save atomically and durably writes account.json with 0600 permissions.
// Uses writeAtomic so a crash or power loss between write and disk flush
// does not leave a truncated file: the FRP token can't be regenerated
// without re-pairing, so durability matters.
func (a *Account) Save() error {
	if a.ServerID == "" {
		return errors.New("server_id is required")
	}
	if a.FRPToken == "" {
		return errors.New("frp_token is required")
	}

	accountPath := AccountPath()
	if err := os.MkdirAll(filepath.Dir(accountPath), 0700); err != nil {
		return fmt.Errorf("create account directory: %w", err)
	}

	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal account: %w", err)
	}

	if err := writeAtomic(accountPath, data, 0600); err != nil {
		return fmt.Errorf("write account file: %w", err)
	}
	return nil
}

// DeleteAccount removes account.json. Used on unpair. Machine state is
// preserved; only the account binding is torn down.
func DeleteAccount() error {
	err := os.Remove(AccountPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete account file: %w", err)
	}
	return nil
}
