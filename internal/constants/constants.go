// Package constants defines application-wide constants to avoid magic numbers.
package constants

import "time"

// Version is the client version, injected at build time via ldflags.
// Default "dev" is used for local/development builds.
var Version = "dev"

// Timing constants for connection management
const (
	HeartbeatInterval = 30 * time.Second // API may override via next_heartbeat_ms
	BaseRetryDelay    = 1 * time.Second
	MaxRetryDelay     = 5 * time.Minute
	HTTPClientTimeout = 30 * time.Second
)

// Polling intervals
const (
	PairPollInterval    = 5 * time.Second
	PairTimeout         = 5 * time.Minute
	WebPairTimeout      = 10 * time.Minute
	StatusPollInterval  = 30 * time.Second
	ServicePollInterval = 30 * time.Second
	StartupDelay        = 5 * time.Second
)

// Default server configuration
const (
	DefaultWebPort     = 8082
	DefaultAPIURL      = "https://api.seawise.io"
	DefaultWebURL      = "https://seawise.io"
	DockerHostInternal = "host.docker.internal"
)

// FRP defaults
const (
	DefaultFRPServerPort = 7000
	DefaultSubdomainHost = "seawise.dev"
	MaxRequestBodySize   = 1024 // 1KB
	MaxAuthBodySize      = 4096 // 4KB — larger for password payloads
)

var AllowedFRPDomains = allowedFRPDomains

const (
	BcryptCost = 12
)

// HTTP server timeouts
const (
	WebUIReadHeaderTimeout = 5 * time.Second
	WebUIReadTimeout       = 15 * time.Second
	WebUIWriteTimeout      = 30 * time.Second
	WebUIIdleTimeout       = 60 * time.Second
)

const (
	DefaultHostname = "seawise-client"
)
