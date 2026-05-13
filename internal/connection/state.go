package connection

import (
	crand "crypto/rand"
	"encoding/binary"
	"log/slog"
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

	heartbeatInterval time.Duration
	baseRetryDelay    time.Duration
	maxRetryDelay     time.Duration

	// Callbacks
	onStateChange func(old, newState State)
	onUnpair      func()
}

type Config struct {
	HeartbeatInterval time.Duration
	BaseRetryDelay    time.Duration
	MaxRetryDelay     time.Duration
}

func DefaultConfig() Config {
	return Config{
		HeartbeatInterval: constants.HeartbeatInterval,
		BaseRetryDelay:    constants.BaseRetryDelay,
		MaxRetryDelay:     constants.MaxRetryDelay,
	}
}

func NewManager(cfg Config) *Manager {
	return &Manager{
		state:             StateDisconnected,
		heartbeatInterval: cfg.HeartbeatInterval,
		baseRetryDelay:    cfg.BaseRetryDelay,
		maxRetryDelay:     cfg.MaxRetryDelay,
	}
}

// SetCallbacks sets the callback functions
func (m *Manager) SetCallbacks(
	onStateChange func(old, newState State),
	onUnpair func(),
) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStateChange = onStateChange
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
		slog.Info("Connection state changed", "component", "connection", "old_state", string(oldState), "new_state", string(newState))
		if callback != nil {
			callback(oldState, newState)
		}
	}
}

// HeartbeatOK reports a successful heartbeat.
func (m *Manager) HeartbeatOK() {
	m.mu.Lock()
	m.lastHeartbeat = time.Now()
	m.lastHeartbeatOK = true
	m.consecutiveFails = 0
	m.reconnectAttempt = 0

	var oldState State
	var changed bool
	if m.state == StateReconnecting || m.state == StateConnecting {
		oldState = m.state
		m.state = StateConnected
		changed = true
	}
	callback := m.onStateChange
	m.mu.Unlock()

	if changed {
		slog.Info("Connection state changed", "component", "connection", "old_state", string(oldState), "new_state", "connected", "trigger", "heartbeat OK")
		if callback != nil {
			callback(oldState, StateConnected)
		}
	}
}

// HeartbeatFailed reports a transient heartbeat failure (network timeout, 5xx,
// DB unavailable, etc.). These MUST NOT count toward unpair — transient
// infrastructure issues should never destroy the client's pairing config.
//
// After the configured threshold of consecutive transient failures, transitions
// to StateReconnecting so FRP restart / backoff logic engages.
func (m *Manager) HeartbeatFailed() {
	m.mu.Lock()
	m.lastHeartbeatOK = false
	m.consecutiveFails++
	fails := m.consecutiveFails
	m.mu.Unlock()

	slog.Warn("Heartbeat failed", "component", "connection", "consecutive_fails", fails)

	if fails >= 3 {
		m.SetState(StateReconnecting)
	}
}

// UnpairRequested fires the onUnpair callback exactly once on the first 410.
// The API only emits 410 after a tombstone or confirm-query proves the row
// is truly deleted, so the client trusts the signal — matches the
// Tailscale / Cloudflare Tunnels / ngrok pattern.
func (m *Manager) UnpairRequested(reason string) bool {
	m.mu.Lock()
	if m.state == StateUnpaired {
		m.mu.Unlock()
		return true
	}
	oldState := m.state
	m.state = StateUnpaired
	unpairCallback := m.onUnpair
	stateCallback := m.onStateChange
	m.mu.Unlock()

	slog.Warn("Server requested unpair", "component", "connection", "reason", reason)
	slog.Info("Connection state changed", "component", "connection", "old_state", string(oldState), "new_state", string(StateUnpaired))
	if stateCallback != nil {
		stateCallback(oldState, StateUnpaired)
	}
	if unpairCallback != nil {
		unpairCallback()
	}
	return true
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

	slog.Info("Backoff calculated", "component", "connection", "attempt", attempt+1, "delay", finalDelay)
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
func (m *Manager) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := map[string]interface{}{
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

// Stop is a no-op retained for interface compatibility.
// The Manager has no background goroutines to stop.
func (m *Manager) Stop() {}
