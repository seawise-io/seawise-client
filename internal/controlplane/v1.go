package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	MaxListItems = 1000
	MinHeartbeat = 10 * time.Second
	MaxHeartbeat = 5 * time.Minute
	DefaultBeat  = 30 * time.Second
	maxNameLen   = 100
	maxHostLen   = 253
	maxTokenLen  = 512
	maxCSRLen    = 16 << 10
)

var (
	uuidRE  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	wordRE  = regexp.MustCompile(`^[a-z_]{1,32}$`)
)

func validUUID(s string) bool { return uuidRE.MatchString(s) }

// ValidSubdomain reports whether s is a single lower-case DNS label.
func ValidSubdomain(s string) bool { return labelRE.MatchString(s) }

func validName(s string) bool {
	return s != "" && len(s) <= maxNameLen && !strings.ContainsFunc(s, isControl)
}

func validHost(s string) bool {
	return s != "" && len(s) <= maxHostLen && !strings.ContainsFunc(s, func(r rune) bool { return isControl(r) || r == ' ' || r == '/' })
}

func validToken(s string) bool {
	if s == "" || len(s) > maxTokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func malformed(op string, format string, a ...any) error {
	return &Error{Op: op, Kind: Transient, Reason: "malformed reply: " + fmt.Sprintf(format, a...)}
}

func invalidArg(op, what string) error {
	return &Error{Op: op, Kind: Rejected, Reason: "invalid " + what}
}

// AllowedFRPHost reports whether addr is inside one of the allowed domains
// (entries starting with "." match subdomains, others match exactly).
func AllowedFRPHost(addr string, allowed []string) bool {
	addr = strings.ToLower(addr)
	if !validHost(addr) || strings.Contains(addr, ":") {
		return false
	}
	for _, a := range allowed {
		a = strings.ToLower(a)
		if strings.HasPrefix(a, ".") {
			if strings.HasSuffix(addr, a) && len(addr) > len(a) {
				return true
			}
			continue
		}
		if addr == a {
			return true
		}
	}
	return false
}

// Pairing.

type PairCodes struct {
	UserCode   string
	DeviceCode string
	ExpiresAt  time.Time
}

func (c *Client) PairRequest(ctx context.Context, serverName string) (*PairCodes, error) {
	const op = "pair request"
	if !validName(serverName) {
		return nil, invalidArg(op, "server name")
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/servers/pair/request", body: map[string]string{"server_name": serverName}, write: true, expectData: true})
	if err != nil {
		return nil, err
	}
	var r struct {
		UserCode   string `json:"user_code"`
		DeviceCode string `json:"device_code"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, malformed(op, "%v", err)
	}
	if !validToken(r.UserCode) || len(r.UserCode) > 32 || !validToken(r.DeviceCode) {
		return nil, malformed(op, "codes")
	}
	exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return nil, malformed(op, "expires_at")
	}
	return &PairCodes{UserCode: r.UserCode, DeviceCode: r.DeviceCode, ExpiresAt: exp}, nil
}

func (c *Client) PairStatus(ctx context.Context, deviceCode string) (string, error) {
	const op = "pair status"
	if !validToken(deviceCode) {
		return "", invalidArg(op, "device code")
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/servers/pair/status", body: map[string]string{"device_code": deviceCode}, idempotent: true, expectData: true})
	if err != nil {
		return "", err
	}
	var r struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &r); err != nil || !wordRE.MatchString(r.Status) {
		return "", malformed(op, "status")
	}
	return r.Status, nil
}

type Pairing struct {
	ServerID      string
	ServerName    string
	UserID        string
	UserEmail     string
	FRPToken      string
	FRPServerAddr string
	FRPServerPort int
	FRPUseTLS     bool
}

func (c *Client) PairComplete(ctx context.Context, deviceCode string) (*Pairing, error) {
	const op = "pair complete"
	if !validToken(deviceCode) {
		return nil, invalidArg(op, "device code")
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/servers/pair/complete", body: map[string]string{"device_code": deviceCode}, write: true, expectData: true})
	if err != nil {
		return nil, err
	}
	return parsePairing(data, c.domains)
}

func parsePairing(data []byte, domains []string) (*Pairing, error) {
	const op = "pair complete"
	var r struct {
		ServerID      string `json:"server_id"`
		ServerName    string `json:"server_name"`
		UserID        string `json:"user_id"`
		UserEmail     string `json:"user_email"`
		FRPToken      string `json:"frp_token"`
		FRPServerAddr string `json:"frp_server_addr"`
		FRPServerPort int    `json:"frp_server_port"`
		FRPUseTLS     *bool  `json:"frp_use_tls"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, malformed(op, "%v", err)
	}
	switch {
	case !validUUID(r.ServerID):
		return nil, malformed(op, "server_id")
	case r.ServerName != "" && !validName(r.ServerName):
		return nil, malformed(op, "server_name")
	case r.UserID != "" && !validUUID(r.UserID):
		return nil, malformed(op, "user_id")
	case len(r.UserEmail) > 320 || strings.ContainsFunc(r.UserEmail, isControl):
		return nil, malformed(op, "user_email")
	case !validToken(r.FRPToken):
		return nil, malformed(op, "frp_token")
	case !AllowedFRPHost(r.FRPServerAddr, domains):
		return nil, malformed(op, "frp_server_addr not allowed")
	case r.FRPServerPort < 1 || r.FRPServerPort > 65535:
		return nil, malformed(op, "frp_server_port")
	case r.FRPUseTLS == nil:
		return nil, malformed(op, "frp_use_tls")
	}
	return &Pairing{
		ServerID: strings.ToLower(r.ServerID), ServerName: r.ServerName, UserID: r.UserID, UserEmail: r.UserEmail,
		FRPToken: r.FRPToken, FRPServerAddr: strings.ToLower(r.FRPServerAddr), FRPServerPort: r.FRPServerPort, FRPUseTLS: *r.FRPUseTLS,
	}, nil
}

func (c *Client) PairCancel(ctx context.Context, deviceCode string) error {
	const op = "pair cancel"
	if !validToken(deviceCode) {
		return invalidArg(op, "device code")
	}
	_, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/servers/pair/cancel", body: map[string]string{"device_code": deviceCode}, idempotent: true, write: true})
	return err
}

// Services.

type Service struct {
	ID        string
	Name      string
	Host      string
	Port      int
	Subdomain string
	Status    string
}

type wireService struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Subdomain string `json:"subdomain"`
	Status    string `json:"status"`
}

// check validates an item; full requires name, host and port (list and
// newly created items), otherwise only id and subdomain are required.
func (w wireService) check(full bool) (Service, error) {
	if !validUUID(w.ID) {
		return Service{}, errors.New("id")
	}
	if full || w.Name != "" || w.Host != "" || w.Port != 0 {
		if !validName(w.Name) {
			return Service{}, errors.New("name")
		}
		if !validHost(w.Host) {
			return Service{}, errors.New("host")
		}
		if w.Port < 1 || w.Port > 65535 {
			return Service{}, errors.New("port")
		}
	}
	if w.Subdomain != "" && !ValidSubdomain(w.Subdomain) {
		return Service{}, errors.New("subdomain")
	}
	if len(w.Status) > 32 || strings.ContainsFunc(w.Status, isControl) {
		return Service{}, errors.New("status")
	}
	return Service{ID: strings.ToLower(w.ID), Name: w.Name, Host: w.Host, Port: w.Port, Subdomain: w.Subdomain, Status: w.Status}, nil
}

func (c *Client) RegisterService(ctx context.Context, serverID, name, host string, port int) (*Service, error) {
	const op = "register service"
	if !validUUID(serverID) {
		return nil, invalidArg(op, "server id")
	}
	if !validName(name) || !validHost(host) || port < 1 || port > 65535 {
		return nil, invalidArg(op, "app")
	}
	// The server upserts by name, so a retry cannot create a duplicate.
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/services/register",
		body: map[string]any{"server_id": serverID, "name": name, "host": host, "port": port},
		auth: true, idempotent: true, write: true, expectData: true})
	if err != nil {
		return nil, err
	}
	var w wireService
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, malformed(op, "%v", err)
	}
	svc, err := w.check(false)
	if err != nil {
		return nil, malformed(op, "%v", err)
	}
	return &svc, nil
}

type ServiceInput struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	IconURL string `json:"icon_url,omitempty"`
}

func (c *Client) RegisterBatch(ctx context.Context, serverID string, in []ServiceInput) ([]Service, error) {
	const op = "register batch"
	if !validUUID(serverID) {
		return nil, invalidArg(op, "server id")
	}
	if len(in) == 0 {
		return []Service{}, nil
	}
	if len(in) > MaxListItems {
		return nil, invalidArg(op, "batch size")
	}
	for _, s := range in {
		if !validName(s.Name) || !validHost(s.Host) || s.Port < 1 || s.Port > 65535 || len(s.IconURL) > 2048 {
			return nil, invalidArg(op, "app")
		}
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/services/register/batch",
		body: map[string]any{"server_id": serverID, "services": in}, auth: true, write: true, expectData: true})
	if err != nil {
		return nil, err
	}
	var r struct {
		Services *[]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.Services == nil {
		return nil, malformed(op, "services")
	}
	out, err := parseItems(op, *r.Services, true)
	if err != nil {
		return nil, err
	}
	if len(out) != len(in) {
		return nil, malformed(op, "%d results for %d apps", len(out), len(in))
	}
	return out, nil
}

func (c *Client) ListServices(ctx context.Context, serverID string) ([]Service, error) {
	const op = "list services"
	if !validUUID(serverID) {
		return nil, invalidArg(op, "server id")
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodGet, path: "/api/servers/" + serverID + "/services", auth: true, idempotent: true, expectData: true})
	if err != nil {
		return nil, err
	}
	return parseServiceList(data)
}

// parseServiceList accepts only a JSON array; null, a missing member or any
// other type is an error, never "no apps".
func parseServiceList(data []byte) ([]Service, error) {
	const op = "list services"
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "[") {
		return nil, malformed(op, "data is not an array")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, malformed(op, "%v", err)
	}
	return parseItems(op, items, true)
}

func parseItems(op string, items []json.RawMessage, full bool) ([]Service, error) {
	if len(items) > MaxListItems {
		return nil, malformed(op, "too many items")
	}
	out := make([]Service, 0, len(items))
	for i, raw := range items {
		if !strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
			return nil, malformed(op, "item %d is not an object", i)
		}
		var w wireService
		if err := json.Unmarshal(raw, &w); err != nil {
			return nil, malformed(op, "item %d: %v", i, err)
		}
		svc, err := w.check(full)
		if err != nil {
			return nil, malformed(op, "item %d: %v", i, err)
		}
		out = append(out, svc)
	}
	return out, nil
}

type Health struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (c *Client) ReportHealth(ctx context.Context, serverID string, statuses []Health) error {
	const op = "report health"
	if !validUUID(serverID) {
		return invalidArg(op, "server id")
	}
	if len(statuses) > MaxListItems {
		return invalidArg(op, "count")
	}
	for _, h := range statuses {
		if !validUUID(h.ID) || (h.Status != "online" && h.Status != "offline") {
			return invalidArg(op, "status")
		}
	}
	if statuses == nil {
		statuses = []Health{}
	}
	_, err := c.do(ctx, call{op: op, method: http.MethodPatch, path: "/api/servers/" + serverID + "/services/health",
		body: map[string]any{"services": statuses}, auth: true, idempotent: true, write: true})
	return err
}

func (c *Client) MarkOffline(ctx context.Context, serverID string) error {
	const op = "mark offline"
	if !validUUID(serverID) {
		return invalidArg(op, "server id")
	}
	_, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/servers/" + serverID + "/offline", auth: true, idempotent: true, write: true})
	return err
}

// Disconnect asks the server to delete this machine. Only an explicit local
// action may call it.
func (c *Client) Disconnect(ctx context.Context, serverID string) error {
	const op = "disconnect"
	if !validUUID(serverID) {
		return invalidArg(op, "server id")
	}
	_, err := c.do(ctx, call{op: op, method: http.MethodDelete, path: "/api/servers/" + serverID + "/disconnect", auth: true, write: true})
	return err
}

func (c *Client) DeleteService(ctx context.Context, serverID, serviceID string) error {
	const op = "delete service"
	if !validUUID(serverID) || !validUUID(serviceID) {
		return invalidArg(op, "id")
	}
	_, err := c.do(ctx, call{op: op, method: http.MethodDelete, path: "/api/servers/" + serverID + "/services/" + serviceID, auth: true, write: true})
	return err
}

// Heartbeat.

type HeartbeatRequest struct {
	FRPConnected  bool   `json:"frp_connected"`
	ServiceCount  int    `json:"service_count"`
	ClientVersion string `json:"client_version"`
	ConnectionID  string `json:"connection_id"`
}

type Endpoint struct {
	Addr string
	Port int
}

type Heartbeat struct {
	Status        string
	ServerStatus  string
	ServerTime    time.Time
	NextHeartbeat time.Duration
	MigrateTo     *Endpoint
	Shard         *Endpoint
}

func (c *Client) Heartbeat(ctx context.Context, serverID string, req HeartbeatRequest) (*Heartbeat, error) {
	const op = "heartbeat"
	if !validUUID(serverID) {
		return nil, invalidArg(op, "server id")
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/servers/" + serverID + "/heartbeat", body: req, auth: true, idempotent: true, write: true, heartbeat: true, expectData: true})
	if err != nil {
		return nil, err
	}
	return parseHeartbeat(data, c.domains)
}

func parseHeartbeat(data []byte, domains []string) (*Heartbeat, error) {
	const op = "heartbeat"
	type wireEndpoint struct {
		Addr string `json:"frp_server_addr"`
		Port int    `json:"frp_server_port"`
	}
	var r struct {
		Status          string        `json:"status"`
		ServerStatus    string        `json:"server_status"`
		ServerTime      string        `json:"server_time"`
		NextHeartbeatMs *int64        `json:"next_heartbeat_ms"`
		MigrateTo       *wireEndpoint `json:"migrate_to"`
		Shard           *wireEndpoint `json:"shard"`
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		return nil, malformed(op, "data is not an object")
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, malformed(op, "%v", err)
	}
	if r.Status != "ok" && r.Status != "migrate" {
		return nil, malformed(op, "status")
	}
	hb := &Heartbeat{Status: r.Status, NextHeartbeat: DefaultBeat}
	if r.ServerStatus != "" {
		if !wordRE.MatchString(r.ServerStatus) {
			return nil, malformed(op, "server_status")
		}
		hb.ServerStatus = r.ServerStatus
	}
	if r.ServerTime != "" {
		t, err := time.Parse(time.RFC3339Nano, r.ServerTime)
		if err != nil {
			return nil, malformed(op, "server_time")
		}
		hb.ServerTime = t
	}
	if r.NextHeartbeatMs != nil {
		d := time.Duration(*r.NextHeartbeatMs) * time.Millisecond
		if *r.NextHeartbeatMs > int64(MaxHeartbeat/time.Millisecond) {
			d = MaxHeartbeat
		}
		hb.NextHeartbeat = min(max(d, MinHeartbeat), MaxHeartbeat)
	}
	endpoint := func(name string, w *wireEndpoint) (*Endpoint, error) {
		if w == nil {
			return nil, nil
		}
		if !AllowedFRPHost(w.Addr, domains) || w.Port < 1 || w.Port > 65535 {
			return nil, malformed(op, "%s outside the allowed FRP servers", name)
		}
		return &Endpoint{Addr: strings.ToLower(w.Addr), Port: w.Port}, nil
	}
	var err error
	if hb.MigrateTo, err = endpoint("migrate_to", r.MigrateTo); err != nil {
		return nil, err
	}
	if hb.Shard, err = endpoint("shard", r.Shard); err != nil {
		return nil, err
	}
	if hb.Status == "migrate" && hb.MigrateTo == nil {
		return nil, malformed(op, "migrate without a target")
	}
	return hb, nil
}

// Certificates. The v1 server answers "E2E disabled" to v2 clients until a
// later phase; these exist so every v1 endpoint has a strict client.

type CertStatus struct {
	E2E           bool
	ACMEDirectory string
}

func (c *Client) CertStatus(ctx context.Context) (*CertStatus, error) {
	const op = "cert status"
	data, err := c.do(ctx, call{op: op, method: http.MethodGet, path: "/api/certs/status", idempotent: true, expectData: true})
	if err != nil {
		return nil, err
	}
	var r struct {
		E2E  *bool  `json:"e2e_tls_enabled"`
		ACME string `json:"acme_directory"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.E2E == nil || len(r.ACME) > 2048 {
		return nil, malformed(op, "status")
	}
	return &CertStatus{E2E: *r.E2E, ACMEDirectory: r.ACME}, nil
}

type Certificate struct {
	PEM       string
	Domain    string
	ExpiresAt time.Time
}

func (c *Client) CertIssue(ctx context.Context, subdomain string, csrPEM []byte) (*Certificate, error) {
	const op = "cert issue"
	if !ValidSubdomain(subdomain) || len(csrPEM) == 0 || len(csrPEM) > maxCSRLen {
		return nil, invalidArg(op, "request")
	}
	data, err := c.do(ctx, call{op: op, method: http.MethodPost, path: "/api/certs/issue",
		body: map[string]string{"subdomain": subdomain, "csr": string(csrPEM)}, auth: true, write: true, expectData: true})
	if err != nil {
		return nil, err
	}
	var r struct {
		Certificate string `json:"certificate"`
		Domain      string `json:"domain"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.Certificate == "" || !validHost(r.Domain) {
		return nil, malformed(op, "certificate")
	}
	exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
	if err != nil {
		return nil, malformed(op, "expires_at")
	}
	return &Certificate{PEM: r.Certificate, Domain: r.Domain, ExpiresAt: exp}, nil
}
