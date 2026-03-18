// Package constants defines application-wide constants to avoid magic numbers.
package constants

import "time"

// Version is the client version, injected at build time via ldflags.
// Default "dev" is used for local/development builds.
var Version = "dev"

// Timing constants for connection management
const (
	// HeartbeatInterval is how often we send heartbeats to the server (default).
	// The API may return a different interval via next_heartbeat_ms in the heartbeat response.
	HeartbeatInterval = 30 * time.Second
	// HeartbeatTimeout is how long to wait for a heartbeat response
	HeartbeatTimeout = 15 * time.Second
	// ServerTimeout is how long before the server marks a client as offline (3 × heartbeat interval)
	ServerTimeout = 90 * time.Second
	// BaseRetryDelay is the initial delay before retrying a failed connection
	BaseRetryDelay = 1 * time.Second
	// MaxRetryDelay caps the exponential backoff for retries
	MaxRetryDelay = 5 * time.Minute
	// HTTPClientTimeout is the timeout for HTTP requests
	HTTPClientTimeout = 30 * time.Second
)

// Polling intervals
const (
	// PairPollInterval is how often to poll for pairing status
	PairPollInterval = 2 * time.Second
	// PairTimeout is the maximum time to wait for pairing (CLI)
	PairTimeout = 5 * time.Minute
	// WebPairTimeout is the maximum time for web UI pairing approval
	// Longer than CLI because users may need time to navigate to dashboard
	WebPairTimeout = 10 * time.Minute
	// StatusPollInterval is how often to poll for status (matches HeartbeatInterval)
	StatusPollInterval = 30 * time.Second
	// ServicePollInterval is how often to poll for service changes
	ServicePollInterval = 30 * time.Second
	// StartupDelay is the initial delay before starting background tasks
	StartupDelay = 5 * time.Second
)

// Default server configuration
const (
	// DefaultWebPort is the default port for the client web UI
	DefaultWebPort = 8082
	// DefaultAPIURL is the default API URL when not specified.
	// Production default — override with SEAWISE_API_URL env var for local development.
	DefaultAPIURL = "https://api.seawise.io"
	// DefaultWebURL is the default web dashboard URL
	// In production, this is the public SeaWise web app.
	// Override with SEAWISE_WEB_URL for local development.
	DefaultWebURL = "https://seawise.io"
	// DockerHostInternal is the Docker host address for container-to-host communication
	DockerHostInternal = "host.docker.internal"
)

// FRP defaults
const (
	// DefaultFRPServerPort is the default FRP server port
	DefaultFRPServerPort = 7000
	// DefaultSubdomainHost is the default subdomain host for service URLs.
	// Production default — override with SUBDOMAIN_HOST env var for local development.
	DefaultSubdomainHost = "seawise.dev"
	// MaxRequestBodySize is the maximum size for HTTP request bodies (1KB)
	MaxRequestBodySize = 1024
	// MaxAuthBodySize is the maximum size for auth request bodies (4KB).
	// Auth payloads include passwords and are intentionally larger than general requests.
	MaxAuthBodySize = 4096
)

// AllowedFRPDomains is the list of trusted FRP server domains.
// See domains_prod.go and domains_dev.go.
var AllowedFRPDomains = allowedFRPDomains

// Security constants
const (
	// BcryptCost is the bcrypt work factor for password hashing
	BcryptCost = 12
)

// HTTP server timeouts for the client web UI
const (
	WebUIReadHeaderTimeout = 5 * time.Second
	WebUIReadTimeout       = 15 * time.Second
	WebUIWriteTimeout      = 30 * time.Second
	WebUIIdleTimeout       = 60 * time.Second
)

// Network defaults
const (
	// DefaultHostname is used when os.Hostname() fails
	DefaultHostname = "seawise-client"
)
