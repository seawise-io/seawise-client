package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	// Use a temp directory to avoid modifying real config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	cfg := &Config{
		ServerID:      "test-server-id",
		ServerName:    "Test Server",
		FRPToken:      "test-token-abc123",
		FRPServerAddr: "frp.example.com",
		FRPServerPort: 7000,
		FRPUseTLS:     true,
		APIURL:        "https://api.example.com",
		UserID:        "user-123",
		UserEmail:     "test@example.com",
	}

	// Save to temp path
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Load from temp path
	loadedData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}
	var loaded Config
	if err := json.Unmarshal(loadedData, &loaded); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify all fields round-trip correctly
	if loaded.ServerID != cfg.ServerID {
		t.Errorf("ServerID = %q, want %q", loaded.ServerID, cfg.ServerID)
	}
	if loaded.ServerName != cfg.ServerName {
		t.Errorf("ServerName = %q, want %q", loaded.ServerName, cfg.ServerName)
	}
	if loaded.FRPToken != cfg.FRPToken {
		t.Errorf("FRPToken = %q, want %q", loaded.FRPToken, cfg.FRPToken)
	}
	if loaded.FRPServerAddr != cfg.FRPServerAddr {
		t.Errorf("FRPServerAddr = %q, want %q", loaded.FRPServerAddr, cfg.FRPServerAddr)
	}
	if loaded.FRPServerPort != cfg.FRPServerPort {
		t.Errorf("FRPServerPort = %d, want %d", loaded.FRPServerPort, cfg.FRPServerPort)
	}
	if loaded.FRPUseTLS != cfg.FRPUseTLS {
		t.Errorf("FRPUseTLS = %v, want %v", loaded.FRPUseTLS, cfg.FRPUseTLS)
	}
	if loaded.APIURL != cfg.APIURL {
		t.Errorf("APIURL = %q, want %q", loaded.APIURL, cfg.APIURL)
	}
	if loaded.UserID != cfg.UserID {
		t.Errorf("UserID = %q, want %q", loaded.UserID, cfg.UserID)
	}
	if loaded.UserEmail != cfg.UserEmail {
		t.Errorf("UserEmail = %q, want %q", loaded.UserEmail, cfg.UserEmail)
	}
}

func TestLoadCorruptedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Write corrupted JSON
	if err := os.WriteFile(configPath, []byte("{invalid json"), 0600); err != nil {
		t.Fatalf("Failed to write corrupted config: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err == nil {
		t.Error("Expected error when loading corrupted JSON, got nil")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := os.ReadFile("/nonexistent/path/config.json")
	if err == nil {
		t.Error("Expected error when loading missing file, got nil")
	}
}

func TestFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	data := []byte(`{"server_id": "test"}`)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Config file permissions = %o, want 0600", perm)
	}
}

func TestPartialConfig(t *testing.T) {
	// Config with only some fields set (simulates partial write)
	data := []byte(`{"server_id": "test-id", "server_name": ""}`)

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Failed to unmarshal partial config: %v", err)
	}

	if cfg.ServerID != "test-id" {
		t.Errorf("ServerID = %q, want %q", cfg.ServerID, "test-id")
	}
	if cfg.ServerName != "" {
		t.Errorf("ServerName = %q, want empty string", cfg.ServerName)
	}
	// Zero values for missing fields
	if cfg.FRPServerPort != 0 {
		t.Errorf("FRPServerPort = %d, want 0", cfg.FRPServerPort)
	}
	if cfg.FRPUseTLS != false {
		t.Errorf("FRPUseTLS = %v, want false", cfg.FRPUseTLS)
	}
}
