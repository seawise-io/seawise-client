// Package localclient provides a client for communicating with the running
// SeaWise server process via its local HTTP API. CLI commands use this to
// proxy operations through the server, ensuring FRP tunnels are updated
// and state stays consistent — the same pattern used by Docker CLI → dockerd
// and Tailscale CLI → tailscaled.
package localclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/seawise/client/internal/constants"
)

// Client communicates with the local SeaWise server process.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New creates a local client pointing at the given port.
func New(port int) *Client {
	return &Client{
		baseURL: fmt.Sprintf("http://localhost:%d", port),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NewDefault creates a local client on the default port.
func NewDefault() *Client {
	return New(constants.DefaultWebPort)
}

// IsRunning checks if the local server is accepting connections.
func (c *Client) IsRunning() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/api/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close() // #nosec G104 — best-effort close on status check
	return resp.StatusCode == http.StatusOK
}

// Status returns the server status as a map.
func (c *Client) Status() (map[string]interface{}, error) {
	return c.getJSON("/api/status")
}

// ListServices returns the list of services.
func (c *Client) ListServices() ([]map[string]interface{}, error) {
	data, err := c.getJSON("/api/services/list")
	if err != nil {
		return nil, err
	}
	services, ok := data["services"].([]interface{})
	if !ok {
		return nil, nil
	}
	var result []map[string]interface{}
	for _, s := range services {
		if m, ok := s.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result, nil
}

// AddService adds a service through the local server (which handles API + FRP).
func (c *Client) AddService(name, host string, port int) (map[string]interface{}, error) {
	body := fmt.Sprintf(`{"name":%q,"host":%q,"port":%d}`, name, host, port)
	return c.postJSON("/api/services/add", body)
}

// DeleteService removes a service through the local server (which handles API + FRP).
func (c *Client) DeleteService(serviceID, serviceName string) (map[string]interface{}, error) {
	body := fmt.Sprintf(`{"service_id":%q,"service_name":%q}`, serviceID, serviceName)
	return c.postJSON("/api/services/delete", body)
}

// Unpair unpairs the server through the local server (which handles cleanup).
func (c *Client) Unpair() (map[string]interface{}, error) {
	return c.postJSON("/api/unpair", "{}")
}

func (c *Client) getJSON(path string) (map[string]interface{}, error) {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(data))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result, nil
}

func (c *Client) postJSON(path, body string) (map[string]interface{}, error) {
	resp, err := c.httpClient.Post(
		c.baseURL+path,
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to extract error message
		var errResp map[string]string
		if json.Unmarshal(data, &errResp) == nil {
			if msg, ok := errResp["error"]; ok {
				return nil, fmt.Errorf("%s", msg)
			}
		}
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(data))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result, nil
}
