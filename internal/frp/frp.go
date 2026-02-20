package frp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/seawise/client/internal/paths"

	"github.com/seawise/client/internal/constants"
)

// tomlEscape escapes a string for safe inclusion in a TOML quoted value.
// Prevents injection of TOML directives via user-controlled service names/subdomains.
func tomlEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

type Config struct {
	ServerAddr string
	ServerPort int
	Token      string
	UserID     string
	ServerID   string
	UseTLS     bool
}

type Service struct {
	Name      string
	LocalIP   string
	LocalPort int
	Subdomain string
	// E2E TLS fields - when set, uses https proxy with local certs
	UseE2ETLS bool
	CertPath  string
	KeyPath   string
}

// ProcessState represents the FRP process state
type ProcessState string

const (
	ProcessStopped  ProcessState = "stopped"
	ProcessStarting ProcessState = "starting"
	ProcessRunning  ProcessState = "running"
	ProcessCrashed  ProcessState = "crashed"
)

type Client struct {
	mu         sync.RWMutex
	config     Config
	services   []Service
	configPath string
	cmd        *exec.Cmd

	// Process monitoring
	state         ProcessState
	lastStartTime time.Time
	crashCount    int
	stopChan      chan struct{}

	// Connection tracking - unique ID per FRP connection for duplicate detection
	// When a new client connects with the same token, it supersedes the old one
	connectionID string

	// Callbacks
	onStateChange func(ProcessState)
}

const frpcTemplate = `serverAddr = "{{ tomlEscape .ServerAddr }}"
serverPort = {{ .ServerPort }}
{{ if .UseTLS }}
# TLS encryption enabled (configured by server)
transport.tls.enable = true
{{ end }}
# Authentication - token and server ID sent via metadata for plugin validation
metadatas.token = "{{ tomlEscape .Token }}"
metadatas.server_id = "{{ tomlEscape .ServerID }}"
metadatas.connection_id = "{{ tomlEscape .ConnectionID }}"

log.to = "console"
log.level = "info"

{{ range .Services }}
[[proxies]]
name = "{{ tomlEscape $.ServerID }}-{{ tomlEscape .Name }}"
{{ if .UseE2ETLS }}
# E2E TLS mode - TLS terminated locally, traffic encrypted end-to-end
type = "https"
[proxies.plugin]
type = "https2http"
localAddr = "{{ tomlEscape .LocalIP }}:{{ .LocalPort }}"
crtPath = "{{ tomlEscape .CertPath }}"
keyPath = "{{ tomlEscape .KeyPath }}"
{{ else }}
# Standard HTTP mode - TLS terminated at gateway
type = "http"
localIP = "{{ tomlEscape .LocalIP }}"
localPort = {{ .LocalPort }}
{{ end }}
subdomain = "{{ tomlEscape .Subdomain }}"
{{ end }}
`

// frpcTmpl is parsed once at package init, not per writeConfigLocked() call
var frpcTmpl = template.Must(template.New("frpc").Funcs(template.FuncMap{
	"tomlEscape": tomlEscape,
}).Parse(frpcTemplate))

func New(cfg Config) *Client {
	configPath := filepath.Join(paths.DataDir(), "frpc.toml")
	log.Printf("[FRP] Config path: %s", configPath)
	return &Client{
		config:     cfg,
		configPath: configPath,
		state:      ProcessStopped,
		stopChan:   make(chan struct{}),
	}
}

// SetOnStateChange sets the callback for process state changes
func (c *Client) SetOnStateChange(callback func(ProcessState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStateChange = callback
}

// State returns the current process state
func (c *Client) State() ProcessState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// IsRunning returns true if the FRP process is running
func (c *Client) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == ProcessRunning && c.cmd != nil && c.cmd.Process != nil
}

// CrashCount returns the number of crashes since last successful start
func (c *Client) CrashCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.crashCount
}

// ConnectionID returns the current connection ID for this FRP session.
// Used by heartbeat to detect when this connection has been superseded.
func (c *Client) ConnectionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connectionID
}

func (c *Client) setState(newState ProcessState) {
	c.mu.Lock()
	oldState := c.state
	c.state = newState
	callback := c.onStateChange
	c.mu.Unlock()

	if oldState != newState {
		log.Printf("[FRP] Process state: %s -> %s", oldState, newState)
		if callback != nil {
			callback(newState)
		}
	}
}

func (c *Client) AddService(svc Service) error {
	c.mu.Lock()
	c.services = append(c.services, svc)
	c.mu.Unlock()
	// Restart FRP to pick up new service
	return c.Restart()
}

// MED-6: Fixed race condition - now uses mutex
func (c *Client) AddServiceWithoutRestart(svc Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.services = append(c.services, svc)
}

// SetServices replaces the current services list without restarting FRP.
// Used by crash recovery to reload services from API before restart.
func (c *Client) SetServices(services []Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.services = services
}

// GetServices returns a copy of the current services list
func (c *Client) GetServices() []Service {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]Service, len(c.services))
	copy(result, c.services)
	return result
}

// RemoveService removes a service by name and restarts FRP
func (c *Client) RemoveService(name string) error {
	c.mu.Lock()
	newServices := []Service{}
	for _, svc := range c.services {
		if svc.Name != name {
			newServices = append(newServices, svc)
		}
	}
	c.services = newServices
	c.mu.Unlock()

	// Restart FRP to apply changes
	return c.Restart()
}

// RemoveServiceWithoutRestart removes a service without restarting FRP
func (c *Client) RemoveServiceWithoutRestart(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	newServices := []Service{}
	for _, svc := range c.services {
		if svc.Name != name {
			newServices = append(newServices, svc)
		}
	}
	c.services = newServices
}

// SyncServices updates the services list to match the provided list and restarts if needed
func (c *Client) SyncServices(apiServices []Service) (added []string, removed []string, err error) {
	c.mu.Lock()

	// Build maps for comparison
	currentMap := make(map[string]Service)
	for _, svc := range c.services {
		currentMap[svc.Name] = svc
	}

	apiMap := make(map[string]Service)
	for _, svc := range apiServices {
		apiMap[svc.Name] = svc
	}

	// Find added and removed services
	for name := range apiMap {
		if _, exists := currentMap[name]; !exists {
			added = append(added, name)
		}
	}
	for name := range currentMap {
		if _, exists := apiMap[name]; !exists {
			removed = append(removed, name)
		}
	}

	// Update services list
	c.services = apiServices
	c.mu.Unlock()

	// Restart if there were changes
	if len(added) > 0 || len(removed) > 0 {
		err = c.Restart()
	}

	return added, removed, err
}

// TranslateLocalhost converts localhost/127.0.0.1 to host.docker.internal
// when running inside Docker, so services on the host are accessible.
// Set SEAWISE_HOST_NETWORK=true to disable translation (for --network host).
func TranslateLocalhost(host string) string {
	if host == "localhost" || host == "127.0.0.1" {
		// Skip translation if using host networking (container shares host's network)
		if os.Getenv("SEAWISE_HOST_NETWORK") == "true" {
			return host
		}
		// Check if we're running in Docker by looking for /.dockerenv
		if _, err := os.Stat("/.dockerenv"); err == nil {
			log.Printf("[FRP] Translating %s -> host.docker.internal (running in Docker)", host)
			return "host.docker.internal"
		}
	}
	return host
}

// WriteConfig writes the FRP config file (acquires lock)
func (c *Client) WriteConfig() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeConfigLocked()
}

// writeConfigLocked writes the FRP config file (caller must hold lock)
func (c *Client) writeConfigLocked() error {
	dir := filepath.Dir(c.configPath)
	log.Printf("[FRP] Creating config dir: %s", dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	log.Printf("[FRP] Writing config to: %s", c.configPath)
	f, err := os.OpenFile(c.configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer f.Close()

	// Translate localhost addresses for Docker compatibility
	translatedServices := make([]Service, len(c.services))
	for i, svc := range c.services {
		translatedServices[i] = Service{
			Name:      svc.Name,
			LocalIP:   TranslateLocalhost(svc.LocalIP),
			LocalPort: svc.LocalPort,
			Subdomain: svc.Subdomain,
			UseE2ETLS: svc.UseE2ETLS,
			CertPath:  svc.CertPath,
			KeyPath:   svc.KeyPath,
		}
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
		ServerAddr:   c.config.ServerAddr,
		ServerPort:   c.config.ServerPort,
		Token:        c.config.Token,
		UseTLS:       c.config.UseTLS,
		ServerID:     c.config.ServerID,
		ConnectionID: c.connectionID,
		Services:     translatedServices,
	}

	if err := frpcTmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Printf("[FRP] Config written with %d services", len(c.services))
	return nil
}

func (c *Client) Start() error {
	c.mu.Lock()

	// Generate new connection ID for this session
	// This allows the server to detect when a newer client takes over
	connIDBytes := make([]byte, 16)
	if _, err := rand.Read(connIDBytes); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to generate connection ID: %w", err)
	}
	c.connectionID = hex.EncodeToString(connIDBytes)
	log.Printf("[FRP] New connection ID: %s", c.connectionID)

	if len(c.services) == 0 {
		log.Printf("[FRP] No services to proxy, skipping start")
		c.mu.Unlock()
		return nil
	}

	// Always rewrite config with fresh connection_id to avoid stale state
	if err := c.writeConfigLocked(); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to write config: %w", err)
	}
	c.mu.Unlock()

	c.setState(ProcessStarting)

	// SECURITY: Only use absolute paths for frpc binary
	// Never use exec.LookPath which searches PATH (command injection risk)
	possiblePaths := []string{
		"/app/frpc",           // Docker container
		"/usr/local/bin/frpc", // Homebrew/manual install
		"/usr/bin/frpc",       // System package
	}
	var frpcPath string
	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			frpcPath = p
			break
		}
	}
	if frpcPath == "" {
		c.setState(ProcessStopped)
		return fmt.Errorf("frpc binary not found in standard locations: %v", possiblePaths)
	}

	log.Printf("[FRP] Starting frpc: %s -c %s", frpcPath, c.configPath)

	c.mu.Lock()
	c.cmd = exec.Command(frpcPath, "-c", c.configPath)
	c.cmd.Stdout = os.Stdout
	c.cmd.Stderr = os.Stderr
	c.lastStartTime = time.Now()

	// Start the process while holding the lock to prevent race with Stop()
	if err := c.cmd.Start(); err != nil {
		c.cmd = nil
		c.mu.Unlock()
		c.setState(ProcessCrashed)
		return fmt.Errorf("failed to start frpc: %w", err)
	}

	// Capture PID while still holding the lock
	var pid int
	if c.cmd.Process != nil {
		pid = c.cmd.Process.Pid
	}
	c.mu.Unlock()

	if pid > 0 {
		log.Printf("[FRP] frpc started with PID %d", pid)
	} else {
		log.Printf("[FRP] frpc started (PID unavailable)")
	}
	c.setState(ProcessRunning)

	// Monitor process in background
	go c.monitorProcess()

	return nil
}

// monitorProcess watches the FRP process and detects crashes
func (c *Client) monitorProcess() {
	c.mu.RLock()
	cmd := c.cmd
	// Capture stopChan BEFORE the blocking Wait() call.
	// Stop() replaces stopChan with a new channel, so we must capture
	// the current one to correctly detect deliberate stops.
	stopCh := c.stopChan
	c.mu.RUnlock()

	if cmd == nil {
		return
	}

	// Wait for process to exit
	err := cmd.Wait()

	// Check if this was a deliberate stop using the captured channel
	select {
	case <-stopCh:
		log.Printf("[FRP] Process stopped deliberately")
		return
	default:
	}

	c.mu.Lock()
	// Process crashed or exited unexpectedly
	c.crashCount++
	crashCount := c.crashCount
	uptime := time.Since(c.lastStartTime)
	c.mu.Unlock()

	c.setState(ProcessCrashed)

	if err != nil {
		log.Printf("[FRP] Process crashed (crash #%d, uptime: %v): %v", crashCount, uptime, err)
	} else {
		log.Printf("[FRP] Process exited unexpectedly (crash #%d, uptime: %v)", crashCount, uptime)
	}
}

// ServiceCount returns the number of services configured
func (c *Client) ServiceCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.services)
}

func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Signal that this is a deliberate stop.
	// monitorProcess captures stopChan before Wait(), so it will see this close.
	select {
	case <-c.stopChan:
		// Already closed
	default:
		close(c.stopChan)
	}

	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Kill()
		// Don't call cmd.Wait() here — monitorProcess is already waiting.
		// Calling Wait() twice causes "waitid: no child processes" errors.
		// Give monitorProcess a moment to detect the kill and exit cleanly.
		c.cmd = nil
	}
	c.state = ProcessStopped

	// Create new stop channel for next Start() call
	c.stopChan = make(chan struct{})

	return nil
}

// ResetCrashCount resets the crash counter (call after successful reconnection)
func (c *Client) ResetCrashCount() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.crashCount = 0
}

// UpdateServer changes the FRP server address and port (used during shard migration).
// SECURITY: Only allows migration to trusted SeaWise domains to prevent redirect attacks.
func (c *Client) UpdateServer(addr string, port int) error {
	// Validate the address is a trusted SeaWise domain
	if !isAllowedFRPDomain(addr) {
		return fmt.Errorf("untrusted FRP server domain: %s", addr)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.ServerAddr = addr
	c.config.ServerPort = port
	return nil
}

// isAllowedFRPDomain checks if the address is a trusted FRP server domain.
func isAllowedFRPDomain(addr string) bool {
	for _, allowed := range constants.AllowedFRPDomains {
		if strings.HasSuffix(addr, allowed) || addr == allowed {
			return true
		}
	}
	return false
}

func (c *Client) Restart() error {
	if err := c.Stop(); err != nil {
		log.Printf("[FRP] Stop error during restart (proceeding): %v", err)
	}
	return c.Start()
}
