package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/paths"
)

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

func ConfigPath() string {
	return filepath.Join(paths.DataDir(), "config.json")
}

func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	configPath := ConfigPath()
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Atomic write: write to temp file, then rename.
	// Prevents corruption if the process crashes mid-write.
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp config file: %w", err)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath) // #nosec G104 — best-effort cleanup, error irrelevant
		return fmt.Errorf("rename config file: %w", err)
	}
	return nil
}

func Exists() bool {
	_, err := os.Stat(ConfigPath())
	return err == nil
}

func Delete() error {
	return os.Remove(ConfigPath())
}

// GetAPIURL resolves the API URL from config, env var, or default (in that order).
func GetAPIURL(cfg *Config) string {
	if cfg != nil && cfg.APIURL != "" {
		return cfg.APIURL
	}
	if url := os.Getenv("SEAWISE_API_URL"); url != "" {
		return url
	}
	return constants.DefaultAPIURL
}

// GetWebURL resolves the web dashboard URL from env var or default.
func GetWebURL() string {
	if url := os.Getenv("SEAWISE_WEB_URL"); url != "" {
		return url
	}
	return constants.DefaultWebURL
}
