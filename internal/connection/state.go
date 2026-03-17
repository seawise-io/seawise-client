package connection

import (
	crand "crypto/rand"
	"encoding/binary"
	"log"
	"math"
	"sync"
	"time"

	"github.com/seawise/client/internal/constants"
)

// State represents the connection state machine
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateReconnecting State = "reconnecting"
	StateUnpaired     State = "unpaired"
)

// Manager handles connection state and reconnection logic
type Manager struct {
	mu sync.RWMutex

	state            State
	lastHeartbeat    time.Time
	lastHeartbeatOK  bool
	consecutiveFails int
	reconnectAttempt int

	// Configuration (based on research)
	heartbeatInterval time.Duration // How often to send heartbeat
	heartbeatTimeout  time.Duration // Max wait for heartbeat response
	serverTimeout     time.Duration // When server marks us offline
	baseRetryDelay    time.Duration // Initial retry delay
	maxRetryDelay     time.Duration // Maximum retry delay

	// Callbacks
	onStateChange func(old, new State)
	onReconnect   func(attempt int) error
	onUnpair      func()

	// Control
	stopChan chan struct{}
	stopOnce sync.Once
}

// Config for connection manager
type Config struct {
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	ServerTimeout     time.Duration
	BaseRetryDelay    time.Duration
	MaxRetryDelay     time.Duration
}

// DefaultConfig returns production-ready defaults
func DefaultConfig() Config {
	return Config{
		HeartbeatInterval: constants.HeartbeatInterval,
		HeartbeatTimeout:  constants.HeartbeatTimeout,
		ServerTimeout:     constants.ServerTimeout,
		BaseRetryDelay:    constants.BaseRetryDelay,
		MaxRetryDelay:     constants.MaxRetryDelay,
	}
}

// NewManager creates a new connection state manager
func NewManager(cfg Config) *Manager {
	return &Manager{
		state:             StateDisconnected,
		heartbeatInterval: cfg.HeartbeatInterval,
		heartbeatTimeout:  cfg.HeartbeatTimeout,
		serverTimeout:     cfg.ServerTimeout,
		baseRetryDelay:    cfg.BaseRetryDelay,
		maxRetryDelay:     cfg.MaxRetryDelay,
		stopChan:          make(chan struct{}),
	}
}

// SetCallbacks sets the callback functions
func (m *Manager) SetCallbacks(
	onStateChange func(old, new State),
	onReconnect func(attempt int) error,
	onUnpair func(),
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStateChange = onStateChange
	m.onReconnect = onReconnect
	m.onUnpair = onUnpair
}

// State returns the current connection state
func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// SetState changes the connection state
func (m *Manager) SetState(newState State) {
	m.mu.Lock()
	oldState := m.state
	m.state = newState
	callback := m.onStateChange
	m.mu.Unlock()

	if oldState != newState {
		log.Printf("[Connection] State: %s -> %s", oldState, newState)
		if callback != nil {
			callback(oldState, newState)
		}
	}
}

// HeartbeatOK reports a successful heartbeat
func (m *Manager) HeartbeatOK() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastHeartbeat = time.Now()
	m.lastHeartbeatOK = true
	m.consecutiveFails = 0
	m.reconnectAttempt = 0

	if m.state == StateReconnecting || m.state == StateConnecting {
		oldState := m.state
		m.state = StateConnected
		log.Printf("[Connection] State: %s -> connected (heartbeat OK)", oldState)
	}
}

// HeartbeatFailed reports a failed heartbeat
func (m *Manager) HeartbeatFailed(shouldUnpair bool) {
	m.mu.Lock()
	m.lastHeartbeatOK = false
	m.consecutiveFails++
	fails := m.consecutiveFails
	unpairCallback := m.onUnpair
	m.mu.Unlock()

	if shouldUnpair {
		log.Printf("[Connection] Server requested unpair")
		m.SetState(StateUnpaired)
		if unpairCallback != nil {
			unpairCallback()
		}
		return
	}

	log.Printf("[Connection] Heartbeat failed (consecutive: %d)", fails)

	// After 3 consecutive failures, enter reconnecting state
	if fails >= 3 {
		m.SetState(StateReconnecting)
	}
}

// CalculateBackoff returns the next retry delay using exponential backoff with jitter
func (m *Manager) CalculateBackoff() time.Duration {
	m.mu.Lock()
	attempt := m.reconnectAttempt
	m.reconnectAttempt++
	m.mu.Unlock()

	// Exponential backoff: base * 2^attempt
	delay := float64(m.baseRetryDelay) * math.Pow(2, float64(attempt))

	// Cap at max delay
	if delay > float64(m.maxRetryDelay) {
		delay = float64(m.maxRetryDelay)
	}

	// Add jitter (0-100% of delay) to prevent thundering herd
	var b [8]byte
	_, _ = crand.Read(b[:])
	jitter := float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64) * delay
	finalDelay := time.Duration(delay + jitter)

	// Cap the final delay after adding jitter to ensure we never exceed maxRetryDelay
	if finalDelay > m.maxRetryDelay {
		finalDelay = m.maxRetryDelay
	}

	log.Printf("[Connection] Backoff: attempt %d, delay %v", attempt+1, finalDelay)
	return finalDelay
}

// ResetBackoff resets the reconnection attempt counter
func (m *Manager) ResetBackoff() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconnectAttempt = 0
}

// LastHeartbeatAge returns how long since the last successful heartbeat
func (m *Manager) LastHeartbeatAge() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastHeartbeat.IsZero() {
		return 0
	}
	return time.Since(m.lastHeartbeat)
}

// ConsecutiveFails returns the number of consecutive heartbeat failures
func (m *Manager) ConsecutiveFails() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.consecutiveFails
}

// GetStatus returns a status map for the UI
func (m *Manager) GetStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := map[string]any{
		"state":             string(m.state),
		"consecutive_fails": m.consecutiveFails,
		"reconnect_attempt": m.reconnectAttempt,
	}

	if !m.lastHeartbeat.IsZero() {
		status["last_heartbeat"] = m.lastHeartbeat.Format(time.RFC3339)
		status["last_heartbeat_ago_ms"] = time.Since(m.lastHeartbeat).Milliseconds()
	}

	return status
}

// Stop stops the connection manager (safe to call multiple times)
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
}
