package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withTempDataDir points paths.DataDir() at a freshly-created directory
// for the duration of the test. Returns the directory so tests can inspect
// the on-disk state.
func withTempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SEAWISE_DATA_DIR", dir)
	return dir
}

func TestConfigJSONRoundTrip(t *testing.T) {
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

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if loaded != *cfg {
		t.Errorf("round-trip mismatch: got %+v, want %+v", loaded, *cfg)
	}
}

func TestMachineSaveAndLoad(t *testing.T) {
	dir := withTempDataDir(t)

	id, err := GenerateMachineID()
	if err != nil {
		t.Fatalf("GenerateMachineID: %v", err)
	}
	m := &Machine{
		MachineID:   id,
		MachineName: "test-box",
		Services: []LocalService{
			{LocalID: "l1", Name: "jellyfin", Host: "127.0.0.1", Port: 8096},
		},
	}
	if err := m.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "machine.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("machine.json permissions = %v, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadMachine()
	if err != nil {
		t.Fatalf("LoadMachine: %v", err)
	}
	if loaded.MachineID != id {
		t.Errorf("MachineID = %q, want %q", loaded.MachineID, id)
	}
	if len(loaded.Services) != 1 || loaded.Services[0].Name != "jellyfin" {
		t.Errorf("Services = %+v, want one jellyfin entry", loaded.Services)
	}
}

func TestMachineSaveRequiresMachineID(t *testing.T) {
	withTempDataDir(t)
	m := &Machine{}
	if err := m.Save(); err == nil {
		t.Error("Save with empty MachineID should fail")
	}
}

func TestLoadMachineNormalizesNilServices(t *testing.T) {
	dir := withTempDataDir(t)
	if err := os.WriteFile(filepath.Join(dir, "machine.json"), []byte(`{"machine_id":"abc"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	m, err := LoadMachine()
	if err != nil {
		t.Fatalf("LoadMachine: %v", err)
	}
	if m.Services == nil {
		t.Error("Services should be non-nil after load")
	}
}

func TestAccountSaveAndLoad(t *testing.T) {
	dir := withTempDataDir(t)

	a := &Account{
		ServerID:      "srv-1",
		ServerName:    "test",
		FRPToken:      "deadbeef",
		FRPServerAddr: "frp.example.com",
		FRPServerPort: 443,
		FRPUseTLS:     true,
		APIURL:        "https://api.example.com",
		UserID:        "u-1",
		UserEmail:     "user@example.com",
	}
	if err := a.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "account.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("account.json permissions = %v, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadAccount()
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if loaded.ServerID != "srv-1" || loaded.FRPToken != "deadbeef" {
		t.Errorf("round-trip mismatch: %+v", loaded)
	}
}

func TestAccountSaveRequiresIDAndToken(t *testing.T) {
	withTempDataDir(t)
	if err := (&Account{FRPToken: "x"}).Save(); err == nil {
		t.Error("Save with empty ServerID should fail")
	}
	if err := (&Account{ServerID: "x"}).Save(); err == nil {
		t.Error("Save with empty FRPToken should fail")
	}
}

func TestDeleteAccountIsIdempotent(t *testing.T) {
	withTempDataDir(t)
	if err := DeleteAccount(); err != nil {
		t.Fatalf("DeleteAccount on missing file: %v", err)
	}
	a := &Account{ServerID: "x", FRPToken: "y"}
	if err := a.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := DeleteAccount(); err != nil {
		t.Fatalf("DeleteAccount first call: %v", err)
	}
	if err := DeleteAccount(); err != nil {
		t.Fatalf("DeleteAccount second call: %v", err)
	}
}

func TestConfigFacadeRoundTrip(t *testing.T) {
	withTempDataDir(t)

	c := &Config{
		ServerID:      "s-1",
		ServerName:    "my-box",
		FRPToken:      "t-1",
		FRPServerAddr: "frp.example.com",
		FRPServerPort: 443,
		FRPUseTLS:     true,
		APIURL:        "https://api.example.com",
		UserID:        "u-1",
		UserEmail:     "user@example.com",
	}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if !Exists() {
		t.Error("Exists should be true after Save")
	}
	if !MachineExists() {
		t.Error("machine.json should exist after Save")
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ServerID != c.ServerID || got.FRPToken != c.FRPToken || got.UserEmail != c.UserEmail {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, c)
	}
}

func TestConfigSavePreservesExistingMachine(t *testing.T) {
	withTempDataDir(t)

	id, _ := GenerateMachineID()
	m := &Machine{
		MachineID: id,
		Services: []LocalService{
			{LocalID: "l1", Name: "existing", Host: "127.0.0.1", Port: 8080},
		},
	}
	if err := m.Save(); err != nil {
		t.Fatalf("seed machine: %v", err)
	}

	c := &Config{ServerID: "s", FRPToken: "t", APIURL: "x"}
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := LoadMachine()
	if err != nil {
		t.Fatalf("LoadMachine: %v", err)
	}
	if loaded.MachineID != id {
		t.Errorf("MachineID was overwritten: got %q, want %q", loaded.MachineID, id)
	}
	if len(loaded.Services) != 1 || loaded.Services[0].Name != "existing" {
		t.Errorf("services list was lost: %+v", loaded.Services)
	}
}

func TestConfigDeleteRemovesAccountAndLegacyOnly(t *testing.T) {
	dir := withTempDataDir(t)

	m := &Machine{MachineID: "m1", Services: []LocalService{}}
	if err := m.Save(); err != nil {
		t.Fatalf("save machine: %v", err)
	}
	a := &Account{ServerID: "s", FRPToken: "t"}
	if err := a.Save(); err != nil {
		t.Fatalf("save account: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"server_id":"s"}`), 0600); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	if err := Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if AccountExists() {
		t.Error("account.json should be gone after Delete")
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Errorf("config.json should be gone after Delete, got err=%v", err)
	}
	if !MachineExists() {
		t.Error("machine.json should survive Delete")
	}
}

func TestMigrateLegacyFreshInstall(t *testing.T) {
	withTempDataDir(t)

	if err := MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if !MachineExists() {
		t.Error("machine.json should exist after fresh-install migration")
	}
	if AccountExists() {
		t.Error("account.json should NOT exist after fresh-install migration")
	}
	m, err := LoadMachine()
	if err != nil {
		t.Fatalf("LoadMachine: %v", err)
	}
	if m.MachineID == "" {
		t.Error("MachineID should be populated")
	}
	if len(m.Services) != 0 {
		t.Error("Services should be empty on fresh install")
	}
}

func TestMigrateLegacyFromConfigJSON(t *testing.T) {
	dir := withTempDataDir(t)

	legacy := Config{
		ServerID:      "srv-legacy",
		ServerName:    "legacy-box",
		FRPToken:      "legacy-token",
		FRPServerAddr: "frp.example.com",
		FRPServerPort: 443,
		FRPUseTLS:     true,
		APIURL:        "https://api.example.com",
		UserID:        "u-legacy",
		UserEmail:     "legacy@example.com",
	}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	if err := MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Error("legacy config.json should be deleted after migration")
	}
	m, err := LoadMachine()
	if err != nil {
		t.Fatalf("LoadMachine: %v", err)
	}
	if m.MachineID == "" {
		t.Error("MachineID should be populated")
	}
	if m.MachineName != "legacy-box" {
		t.Errorf("MachineName = %q, want %q", m.MachineName, "legacy-box")
	}

	a, err := LoadAccount()
	if err != nil {
		t.Fatalf("LoadAccount: %v", err)
	}
	if a.ServerID != "srv-legacy" || a.FRPToken != "legacy-token" {
		t.Errorf("account not migrated correctly: %+v", a)
	}
}

func TestMigrateLegacyIsIdempotent(t *testing.T) {
	dir := withTempDataDir(t)

	legacy := Config{ServerID: "s", ServerName: "n", FRPToken: "t", FRPServerAddr: "h", FRPServerPort: 1, APIURL: "a", UserID: "u", UserEmail: "e"}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := MigrateLegacy(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	firstMachine, err := LoadMachine()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if err := MigrateLegacy(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	secondMachine, err := LoadMachine()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if firstMachine.MachineID != secondMachine.MachineID {
		t.Error("MachineID should be stable across idempotent migrations")
	}
}

// SEA-162: legacy config.json is cleaned up only when both machine.json
// and account.json exist (= migration genuinely complete). Seeds all
// three files and asserts the legacy is removed. The companion test
// TestMigrateLegacyPreservesLegacyOnPartialMigration covers the case
// where account.json is missing (cleanup must NOT happen).
func TestMigrateLegacyCleansStaleConfigFileAfterFullMigration(t *testing.T) {
	dir := withTempDataDir(t)

	m := &Machine{MachineID: "abc", Services: []LocalService{}}
	if err := m.Save(); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	a := &Account{ServerID: "s", FRPToken: "t"}
	if err := a.Save(); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"server_id":"stale"}`), 0600); err != nil {
		t.Fatalf("seed stale config: %v", err)
	}

	if err := MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Error("stale config.json should be cleaned up after full migration")
	}
}

// SEA-162: when a previous migration crashed between writing machine.json
// and writing account.json, the legacy file is the only remaining record
// of the user's account binding. MigrateLegacy must NOT delete it on
// subsequent runs — the user needs it to recover.
func TestMigrateLegacyPreservesLegacyOnPartialMigration(t *testing.T) {
	dir := withTempDataDir(t)

	m := &Machine{MachineID: "abc", Services: []LocalService{}}
	if err := m.Save(); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	// Legacy file has the original (unrecovered) account data. Account.json
	// is intentionally absent — that's the partial-migration state.
	legacy := []byte(`{"server_id":"recoverable","frp_token":"original"}`)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), legacy, 0600); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	if err := MigrateLegacy(); err != nil {
		t.Fatalf("MigrateLegacy: %v", err)
	}

	// Legacy must still exist — it's the only record of the account binding.
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Errorf("legacy config.json must be preserved on partial-migration state, got err=%v", err)
	}
	// Account.json must still NOT exist — MigrateLegacy is not allowed to
	// invent account state from a stale legacy file when machine.json
	// already exists (the machine_id mismatch would be silent corruption).
	if AccountExists() {
		t.Error("account.json must not be auto-created from legacy when machine.json already exists")
	}
}

func TestGenerateMachineIDIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := GenerateMachineID()
		if err != nil {
			t.Fatalf("GenerateMachineID: %v", err)
		}
		if len(id) != 32 {
			t.Errorf("id length = %d, want 32 hex chars", len(id))
		}
		if seen[id] {
			t.Errorf("duplicate id: %q", id)
		}
		seen[id] = true
	}
}

func TestCorruptedMachineReturnsError(t *testing.T) {
	dir := withTempDataDir(t)
	if err := os.WriteFile(filepath.Join(dir, "machine.json"), []byte("{invalid"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadMachine(); err == nil {
		t.Error("LoadMachine should error on corrupt file")
	}
}

func TestCorruptedAccountReturnsError(t *testing.T) {
	dir := withTempDataDir(t)
	if err := os.WriteFile(filepath.Join(dir, "account.json"), []byte("{invalid"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadAccount(); err == nil {
		t.Error("LoadAccount should error on corrupt file")
	}
}
