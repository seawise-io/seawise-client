package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/validation"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	mu         sync.RWMutex
	frpToken   string
}

func New(baseURL string) *Client {
	// Validate URL uses HTTPS in production (non-localhost)
	// Log warning but don't fail - allows gradual enforcement
	if err := ValidateBaseURL(baseURL); err != nil {
		// Import log is already available via other usages
		log.Printf("[API] WARNING: %v", err)
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: constants.HTTPClientTimeout,
		},
	}
}

// ValidateBaseURL checks that the API URL uses HTTPS in production
// SECURITY: FRP tokens are sent in headers - MUST use HTTPS to prevent interception
func ValidateBaseURL(baseURL string) error {
	// Allow HTTP only for localhost/development
	if strings.HasPrefix(baseURL, "http://localhost") ||
		strings.HasPrefix(baseURL, "http://127.0.0.1") ||
		strings.HasPrefix(baseURL, "http://[::1]") {
		return nil
	}

	// All other URLs must use HTTPS
	if !strings.HasPrefix(baseURL, "https://") {
		return fmt.Errorf("API URL must use HTTPS for security (got: %s)", baseURL)
	}

	return nil
}

// isSuccessStatus returns true for any 2xx HTTP status code
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// PairingCodes holds both codes from pairing request
type PairingCodes struct {
	UserCode   string    // Show to user (10 chars)
	DeviceCode string    // Keep secret, use for polling (32 chars)
	ExpiresAt  time.Time
}

// InitPairing starts the pairing process and returns both codes
func (c *Client) InitPairing(serverName string) (*PairingCodes, error) {
	result, err := c.RequestPairing(serverName)
	if err != nil {
		return nil, fmt.Errorf("init pairing: %w", err)
	}

	// Parse expiration time (use default 10 min from now if parsing fails)
	expTime, parseErr := time.Parse(time.RFC3339, result.ExpiresAt)
	if parseErr != nil {
		expTime = time.Now().Add(10 * time.Minute)
	}

	return &PairingCodes{
		UserCode:   result.UserCode,
		DeviceCode: result.DeviceCode,
		ExpiresAt:  expTime,
	}, nil
}

func (c *Client) SetFRPToken(token string) {
	c.mu.Lock()
	c.frpToken = token
	c.mu.Unlock()
}

// getFRPToken returns the current FRP token (thread-safe)
func (c *Client) getFRPToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.frpToken
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

// Request a new pairing code from the API
// Returns two codes (OAuth Device Flow pattern):
// - UserCode: 10 chars, shown to user
// - DeviceCode: 32 chars, used by client for polling/completion (never shown)
type PairRequestResponse struct {
	UserCode   string `json:"user_code"`   // Show this to user
	DeviceCode string `json:"device_code"` // Keep secret, use for polling
	ExpiresAt  string `json:"expires_at"`
}

func (c *Client) RequestPairing(serverName string) (*PairRequestResponse, error) {
	payload := map[string]string{"server_name": serverName}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/servers/pair/request", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create pairing request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send pairing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("request pairing failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result struct {
		Data PairRequestResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &result.Data, nil
}

// PollPairingStatus polls for approval using device_code (OAuth Device Flow)
func (c *Client) PollPairingStatus(deviceCode string) (string, error) {
	payload := map[string]string{"device_code": deviceCode}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/servers/pair/status", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send poll request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("poll status failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return result.Data.Status, nil
}

type PairCompleteRequest struct {
	DeviceCode string `json:"device_code"` // Use device_code (OAuth Device Flow)
}

type PairCompleteResponse struct {
	Data struct {
		ServerID      string `json:"server_id"`
		ServerName    string `json:"server_name"`
		FRPToken      string `json:"frp_token"`
		FRPServerAddr string `json:"frp_server_addr"`
		FRPServerPort int    `json:"frp_server_port"`
		FRPUseTLS     bool   `json:"frp_use_tls"`
		UserID        string `json:"user_id"`
		UserEmail     string `json:"user_email"`
	} `json:"data"`
}

// CompletePairing completes the pairing using device_code
func (c *Client) CompletePairing(deviceCode string) (*PairCompleteResponse, error) {
	payload := PairCompleteRequest{DeviceCode: deviceCode}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal complete request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/servers/pair/complete", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create complete request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send complete request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read complete response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("pairing failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result PairCompleteResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse complete response: %w", err)
	}

	return &result, nil
}

type Service struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Subdomain string `json:"subdomain"`
	Status    string `json:"status"`
}

type RegisterServiceRequest struct {
	ServerID string `json:"server_id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

func (c *Client) RegisterService(serverID, name, host string, port int) (*Service, error) {
	payload := RegisterServiceRequest{
		ServerID: serverID,
		Name:     name,
		Host:     host,
		Port:     port,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal service request: %w", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/services/register", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create service request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send service request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read service response: %w", err)
	}

	if !isSuccessStatus(resp.StatusCode) {
		return nil, fmt.Errorf("register service failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result struct {
		Data Service `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse service response: %w", err)
	}

	return &result.Data, nil
}

// MigrateInfo contains the new FRP shard to connect to during migration
type MigrateInfo struct {
	FRPServerAddr string `json:"frp_server_addr"`
	FRPServerPort int    `json:"frp_server_port"`
	ShardID       string `json:"shard_id"`
}

// ShardInfo contains the current shard address from the server
// Used for self-healing when the client's stored address is stale
type ShardInfo struct {
	FRPServerAddr string `json:"frp_server_addr"`
	FRPServerPort int    `json:"frp_server_port"`
}

// HeartbeatResponse contains the bidirectional status from the server
type HeartbeatResponse struct {
	Status          string       `json:"status"`
	ServerStatus    string       `json:"server_status"`
	ServerTime      string       `json:"server_time"`
	PreviousStatus  string       `json:"previous_status"`
	GapSeconds      int          `json:"gap_seconds"`
	NextHeartbeatMs int          `json:"next_heartbeat_ms"`
	TimeoutMs       int          `json:"timeout_ms"`
	MigrateTo       *MigrateInfo `json:"migrate_to,omitempty"`
	Shard           *ShardInfo   `json:"shard,omitempty"`
}

// HeartbeatResult contains the result of a heartbeat call
type HeartbeatResult struct {
	Success      bool
	ShouldUnpair bool // Server says we should unpair (server deleted)
	Superseded   bool // Another client took over this connection
	Response     *HeartbeatResponse
	Error        error
}

func (c *Client) Heartbeat(serverID string, frpConnected bool, serviceCount int, clientVersion string, connectionID string) HeartbeatResult {
	// Build request with client status
	payload := map[string]interface{}{
		"frp_connected":  frpConnected,
		"service_count":  serviceCount,
		"client_version": clientVersion,
		"connection_id":  connectionID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return HeartbeatResult{Error: fmt.Errorf("marshal request: %w", err)}
	}

	req, err := http.NewRequest("POST", c.baseURL+"/api/servers/"+serverID+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return HeartbeatResult{Error: fmt.Errorf("create heartbeat request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return HeartbeatResult{Error: fmt.Errorf("send heartbeat request: %w", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return HeartbeatResult{Error: fmt.Errorf("read response: %w", err)}
	}

	// Check for 410 Gone - server was deleted
	if resp.StatusCode == 410 {
		return HeartbeatResult{
			Success:      false,
			ShouldUnpair: true,
			Error:        fmt.Errorf("server deleted"),
		}
	}

	// Check for 409 Conflict - connection superseded by newer client
	if resp.StatusCode == 409 {
		return HeartbeatResult{
			Success:    false,
			Superseded: true,
			Error:      fmt.Errorf("connection superseded by another client"),
		}
	}

	if resp.StatusCode != 200 {
		return HeartbeatResult{
			Error: fmt.Errorf("heartbeat failed: status %d", resp.StatusCode),
		}
	}

	var result struct {
		Data HeartbeatResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return HeartbeatResult{
			Success: false,
			Error:   fmt.Errorf("parse heartbeat response: %w", err),
		}
	}

	return HeartbeatResult{
		Success:  true,
		Response: &result.Data,
	}
}

func (c *Client) ListServices(serverID string) ([]Service, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/servers/"+serverID+"/services", nil)
	if err != nil {
		return nil, fmt.Errorf("create list services request: %w", err)
	}
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send list services request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read services response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list services failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result struct {
		Data []Service `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse services response: %w", err)
	}

	return result.Data, nil
}

type ServiceHealthStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (c *Client) ReportServiceHealth(serverID string, statuses []ServiceHealthStatus) error {
	payload, err := json.Marshal(map[string]interface{}{
		"services": statuses,
	})
	if err != nil {
		return fmt.Errorf("marshal health status: %w", err)
	}

	req, err := http.NewRequest("PATCH", c.baseURL+"/api/servers/"+serverID+"/services/health", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create health report request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send health report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report health failed: %s (status %d)", string(body), resp.StatusCode)
	}

	return nil
}

// MarkOffline notifies the API that this server is going offline.
// Marks server/services offline and revokes active sessions.
// Used on graceful shutdown, crash recovery, and superseded responses.
func (c *Client) MarkOffline(serverID string) error {
	req, err := http.NewRequest("POST", c.baseURL+"/api/servers/"+serverID+"/offline", nil)
	if err != nil {
		return fmt.Errorf("create offline request: %w", err)
	}
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send offline request: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccessStatus(resp.StatusCode) {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mark offline failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}
	return nil
}

func (c *Client) DeleteServer(serverID string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/api/servers/"+serverID+"/disconnect", nil)
	if err != nil {
		return fmt.Errorf("create disconnect request: %w", err)
	}
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send disconnect request: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccessStatus(resp.StatusCode) {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete server failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}
	return nil
}

// DeleteService deletes a service from the server
func (c *Client) DeleteService(serverID, serviceID string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/api/servers/"+serverID+"/services/"+serviceID, nil)
	if err != nil {
		return fmt.Errorf("create delete service request: %w", err)
	}
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send delete service request: %w", err)
	}
	defer resp.Body.Close()

	if !isSuccessStatus(resp.StatusCode) {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete service failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}
	return nil
}

// CertStatusResponse contains E2E TLS status info
type CertStatusResponse struct {
	E2ETLSEnabled bool   `json:"e2e_tls_enabled"`
	ACMEDirectory string `json:"acme_directory"`
}

// CertIssueResponse contains the issued certificate
type CertIssueResponse struct {
	Certificate string `json:"certificate"`
	Domain      string `json:"domain"`
	ExpiresAt   string `json:"expires_at"`
}

// GetCertStatus checks if E2E TLS is enabled on the server
func (c *Client) GetCertStatus() (*CertStatusResponse, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/api/certs/status", nil)
	if err != nil {
		return nil, fmt.Errorf("create cert status request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send cert status request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cert status response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("get cert status failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result struct {
		Data CertStatusResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse cert status response: %w", err)
	}

	return &result.Data, nil
}

// RequestCertificate requests a TLS certificate for a subdomain
func (c *Client) RequestCertificate(subdomain string, csrPEM []byte) (*CertIssueResponse, error) {
	payload := map[string]string{
		"subdomain": subdomain,
		"csr":       string(csrPEM),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal cert request: %w", err)
	}

	// Certificate issuance can take time due to DNS propagation — use longer timeout via context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/certs/issue", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create cert issue request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FRP-Token", c.getFRPToken())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send cert issue request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cert response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("request certificate failed: %s", validation.ParseAPIError(respBody, resp.StatusCode))
	}

	var result struct {
		Data CertIssueResponse `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse cert response: %w", err)
	}

	return &result.Data, nil
}
