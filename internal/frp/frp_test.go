package frp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

func TestTomlEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain string", "hello", "hello"},
		{"double quotes", `say "hello"`, `say \"hello\"`},
		{"backslash", `path\to\file`, `path\\to\\file`},
		{"newline", "line1\nline2", `line1\nline2`},
		{"carriage return", "line1\rline2", `line1\rline2`},
		{"tab", "col1\tcol2", `col1\tcol2`},
		{"combined special chars", "a\"b\\c\nd", `a\"b\\c\nd`},
		{"empty string", "", ""},
		{"toml injection attempt", "value\"\n[malicious]\nkey = \"pwned", `value\"\n[malicious]\nkey = \"pwned`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tomlEscape(tt.input)
			if result != tt.expected {
				t.Errorf("tomlEscape(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTemplateRendering(t *testing.T) {
	tmpl, err := template.New("frpc").Funcs(template.FuncMap{
		"tomlEscape": tomlEscape,
	}).Parse(frpcTemplate)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	data := struct {
		ServerAddr   string
		ServerPort   int
		Token        string
		UseTLS       bool
		ServerID     string
		ConnectionID string
		Services     []Service
	}{
		ServerAddr:   "frp.example.com",
		ServerPort:   7000,
		Token:        "secret-token-123",
		UseTLS:       false,
		ServerID:     "server-abc",
		ConnectionID: "conn-123",
		Services: []Service{
			{
				Name:      "my-app",
				LocalIP:   "192.168.1.100",
				LocalPort: 8080,
				Subdomain: "myapp",
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	output := buf.String()

	// Verify key fields are present
	if !strings.Contains(output, `serverAddr = "frp.example.com"`) {
		t.Error("Missing serverAddr in output")
	}
	if !strings.Contains(output, "serverPort = 7000") {
		t.Error("Missing serverPort in output")
	}
	if !strings.Contains(output, `metadatas.token = "secret-token-123"`) {
		t.Error("Missing token in output")
	}
	if !strings.Contains(output, `name = "server-abc-my-app"`) {
		t.Error("Missing proxy name in output")
	}
	if !strings.Contains(output, `subdomain = "myapp"`) {
		t.Error("Missing subdomain in output")
	}
}

func TestTemplateInjectionPrevention(t *testing.T) {
	tmpl, err := template.New("frpc").Funcs(template.FuncMap{
		"tomlEscape": tomlEscape,
	}).Parse(frpcTemplate)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	// Adversarial input: service name containing TOML injection
	data := struct {
		ServerAddr   string
		ServerPort   int
		Token        string
		UseTLS       bool
		ServerID     string
		ConnectionID string
		Services     []Service
	}{
		ServerAddr:   "frp.example.com",
		ServerPort:   7000,
		Token:        "token",
		ServerID:     "server1",
		ConnectionID: "conn-456",
		Services: []Service{
			{
				Name:      "evil\"\n[[proxies]]\nname = \"injected",
				LocalIP:   "127.0.0.1",
				LocalPort: 8080,
				Subdomain: "test\"\ntype = \"tcp",
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	output := buf.String()

	// Verify newlines in service names are escaped (no raw newlines in output)
	// tomlEscape converts \n to literal \n sequence, keeping the value inside the TOML string
	lines := strings.Split(output, "\n")
	proxySections := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// A real TOML section header is [[proxies]] at the start of a line, not inside a string
		if trimmed == "[[proxies]]" {
			proxySections++
		}
	}
	if proxySections != 1 {
		t.Errorf("Expected exactly 1 [[proxies]] section header, got %d. Injection may have succeeded.\nOutput:\n%s", proxySections, output)
	}

	// The escaped quotes should be present (not raw quotes)
	if strings.Contains(output, "name = \"injected\"") {
		t.Error("TOML injection succeeded — adversarial proxy name was injected")
	}
}

func TestTemplateWithE2ETLS(t *testing.T) {
	tmpl, err := template.New("frpc").Funcs(template.FuncMap{
		"tomlEscape": tomlEscape,
	}).Parse(frpcTemplate)
	if err != nil {
		t.Fatalf("Failed to parse template: %v", err)
	}

	data := struct {
		ServerAddr   string
		ServerPort   int
		Token        string
		UseTLS       bool
		ServerID     string
		ConnectionID string
		Services     []Service
	}{
		ServerAddr:   "frp.example.com",
		ServerPort:   7000,
		Token:        "token",
		UseTLS:       true,
		ServerID:     "server1",
		ConnectionID: "conn-789",
		Services: []Service{
			{
				Name:      "secure-app",
				LocalIP:   "192.168.1.1",
				LocalPort: 443,
				Subdomain: "secure",
				UseE2ETLS: true,
				CertPath:  "/certs/secure.crt",
				KeyPath:   "/certs/secure.key",
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("Failed to execute template: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "transport.tls.enable = true") {
		t.Error("Missing TLS transport config")
	}
	if !strings.Contains(output, `transport.tls.serverName = "frp.example.com"`) {
		t.Error("Missing TLS serverName — frpc would skip cert verification")
	}
	if !strings.Contains(output, `transport.tls.trustedCaFile = "/etc/ssl/certs/ca-certificates.crt"`) {
		t.Error("Missing TLS trustedCaFile — frpc defaults to InsecureSkipVerify=true without it")
	}
	if !strings.Contains(output, `type = "https"`) {
		t.Error("Missing https proxy type for E2E TLS service")
	}
	if !strings.Contains(output, `type = "https2http"`) {
		t.Error("Missing https2http plugin type")
	}
	if !strings.Contains(output, `crtPath = "/certs/secure.crt"`) {
		t.Error("Missing cert path")
	}
	if !strings.Contains(output, `keyPath = "/certs/secure.key"`) {
		t.Error("Missing key path")
	}
}

func TestWriteConfigPermissions(t *testing.T) {
	// Create a temp directory for the test
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "frpc.toml")

	client := &Client{
		config: Config{
			ServerAddr: "frp.example.com",
			ServerPort: 7000,
			Token:      "test-token",
			ServerID:   "test-server",
		},
		configPath: configPath,
		services: []Service{
			{
				Name:      "test",
				LocalIP:   "127.0.0.1",
				LocalPort: 8080,
				Subdomain: "test",
			},
		},
	}

	if err := client.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Config file permissions = %o, want 0600", perm)
	}

	// Verify content is valid
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config: %v", err)
	}

	if !strings.Contains(string(content), `serverAddr = "frp.example.com"`) {
		t.Error("Config file missing expected content")
	}
}

// TestCloseTerminallyBlocksStart verifies the SEA-219 orphan-frpc guard: a
// *Client captured by a background goroutine cannot start a frpc process
// after Close has been called on it (which handleUnpairInternal does when
// the user unpairs mid-restart-delay).
func TestCloseTerminallyBlocksStart(t *testing.T) {
	c := New(Config{ServerAddr: "frp.example.com", ServerPort: 7000, Token: "tok", ServerID: "srv"})
	c.SetServices([]Service{{Name: "app", LocalIP: "127.0.0.1", LocalPort: 8080, Subdomain: "app"}})

	if c.IsClosed() {
		t.Fatal("fresh client reports closed")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !c.IsClosed() {
		t.Fatal("client not marked closed after Close")
	}

	if err := c.Start(); !errors.Is(err, ErrClientClosed) {
		t.Errorf("Start after Close: got %v, want ErrClientClosed", err)
	}
	if err := c.Restart(); !errors.Is(err, ErrClientClosed) {
		t.Errorf("Restart after Close: got %v, want ErrClientClosed", err)
	}
}

// TestCloseIsIdempotent verifies repeated Close calls are safe. handleUnpairInternal
// races with the shutdown path (which also touches the client); a second Close
// must not panic or double-close channels.
func TestCloseIsIdempotent(t *testing.T) {
	c := New(Config{ServerAddr: "frp.example.com", ServerPort: 7000, Token: "tok", ServerID: "srv"})
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestStopDoesNotClose verifies Stop remains eligible for Stop→Start restart
// cycles (frp_recovery, superseded restart, migrate). Only Close is terminal.
func TestStopDoesNotClose(t *testing.T) {
	c := New(Config{ServerAddr: "frp.example.com", ServerPort: 7000, Token: "tok", ServerID: "srv"})
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.IsClosed() {
		t.Error("Stop should not mark closed — only Close does")
	}
}

func TestBlockedHostsNeverReachConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "frpc.toml")
	client := &Client{
		config:     Config{ServerAddr: "frp.example.com", ServerPort: 7000, Token: "tok", ServerID: "srv"},
		configPath: configPath,
	}

	client.SetServices([]Service{
		{Name: "nas", LocalIP: "192.168.1.20", LocalPort: 5000, Subdomain: "nas"},
		{Name: "meta", LocalIP: "169.254.169.254", LocalPort: 80, Subdomain: "meta"},
	})
	if got := client.ServiceCount(); got != 1 {
		t.Fatalf("SetServices kept %d services, want 1", got)
	}

	client.AddServiceWithoutRestart(Service{Name: "ecs", LocalIP: "169.254.170.2", LocalPort: 80, Subdomain: "ecs"})
	if got := client.ServiceCount(); got != 1 {
		t.Fatalf("AddServiceWithoutRestart accepted a blocked host, count = %d", got)
	}

	if err := client.AddService(Service{Name: "v6", LocalIP: "fe80::1", LocalPort: 80, Subdomain: "v6"}); err == nil {
		t.Fatal("AddService accepted a link-local host")
	}

	// Backstop: a blocked host that got into c.services is still left out of the file.
	client.mu.Lock()
	client.services = append(client.services, Service{Name: "sneaky", LocalIP: "169.254.169.254", LocalPort: 80, Subdomain: "sneaky"})
	client.mu.Unlock()
	if err := client.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "169.254") {
		t.Errorf("blocked host written to frpc config:\n%s", content)
	}
	if !strings.Contains(string(content), "192.168.1.20") {
		t.Error("allowed host missing from frpc config")
	}
}
