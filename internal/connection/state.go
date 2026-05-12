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

	// Unpair confirmation: the API can only destroy pairing config on a
	// sustained signal, not a single 410. See UnpairRequested.
	unpairSignals    int
	firstUnpairAt    time.Time
	lastUnpairReason string

	// Thresholds (injected via Config so tests can lower them)
	unpairCount  int
	unpairWindow time.Duration

	// Configuration
	heartbeatInterval time.Duration // How often to send heartbeat
	baseRetryDelay    time.Duration // Initial retry delay
	maxRetryDelay     time.Duration // Maximum retry delay

	// Callbacks
	onStateChange func(old, newState State)
	onUnpair      func()
}

// Config for connection manager
type Config struct {
	HeartbeatInterval time.Duration
	BaseRetryDelay    time.Duration
	MaxRetryDelay     time.Duration
	UnpairCount       int
	UnpairWindow      time.Duration
}

// DefaultConfig returns production-ready defaults
func DefaultConfig() Config {
	return Config{
		HeartbeatInterval: constants.HeartbeatInterval,
		BaseRetryDelay:    constants.BaseRetryDelay,
		MaxRetryDelay:     constants.MaxRetryDelay,
		UnpairCount:       constants.UnpairConfirmationCount,
		UnpairWindow:      constants.UnpairConfirmationWindow,
	}
}

// NewManager creates a new connection state manager
func NewManager(cfg Config) *Manager {
	if cfg.UnpairCount <= 0 {
		cfg.UnpairCount = constants.UnpairConfirmationCount
	}
	if cfg.UnpairWindow <= 0 {
		cfg.UnpairWindow = constants.UnpairConfirmationWindow
	}
	return &Manager{
		state:             StateDisconnected,
		heartbeatInterval: cfg.HeartbeatInterval,
		baseRetryDelay:    cfg.BaseRetryDelay,
		maxRetryDelay:     cfg.MaxRetryDelay,
		unpairCount:       cfg.UnpairCount,
		unpairWindow:      cfg.UnpairWindow,
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

// HeartbeatOK reports a successful heartbeat. Also clears any pending unpair
// signals — a successful response means the server acknowledges the pairing,
// so any earlier 410 was transient and should not count toward confirmation.
func (m *Manager) HeartbeatOK() {
	m.mu.Lock()
	m.lastHeartbeat = time.Now()
	m.lastHeartbeatOK = true
	m.consecutiveFails = 0
	m.reconnectAttempt = 0
	m.unpairSignals = 0
	m.firstUnpairAt = time.Time{}
	m.lastUnpairReason = ""

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

// UnpairRequested records a server-initiated unpair signal (HTTP 410).
// Returns true only when the signal has been confirmed: at least unpairCount
// consecutive 410 responses AND at least unpairWindow elapsed since the first
// signal. The caller should actually wipe config only when this returns true.
//
// Rationale: wiping pairing is destructive and irreversible. A single 410 from
// a bug, outage, replica lag, or misconfiguration should not nuke the client.
// Legitimate server deletions send 410 on every heartbeat for far longer than
// the window, so the threshold has no practical effect on real deletions.
func (m *Manager) UnpairRequested(reason string) bool {
	now := time.Now()

	m.mu.Lock()
	// Already unpaired — destructive wipe must run at most once per process.
	// Subsequent 410s would otherwise re-fire onUnpair and spam error logs
	// from DeleteAccount (file already gone on the second pass).
	if m.state == StateUnpaired {
		m.mu.Unlock()
		return true
	}
	if m.unpairSignals == 0 {
		m.firstUnpairAt = now
	}
	m.unpairSignals++
	signals := m.unpairSignals
	firstAt := m.firstUnpairAt
	threshold := m.unpairCount
	window := m.unpairWindow
	m.lastUnpairReason = reason
	m.mu.Unlock()

	elapsed := now.Sub(firstAt)
	confirmed := signals >= threshold && elapsed >= window

	slog.Warn(
		"Server requested unpair",
		"component", "connection",
		"reason", reason,
		"signals", signals,
		"threshold", threshold,
		"elapsed", elapsed,
		"window", window,
		"confirmed", confirmed,
	)

	if !confirmed {
		return false
	}

	// Claim the transition atomically: flip to StateUnpaired under the lock
	// so a racing confirmed caller sees the new state and skips the wipe.
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

	slog.Info("Connection state changed", "component", "connection", "old_state", string(oldState), "new_state", string(StateUnpaired))
	slog.Info("Unpair confirmed, wiping pairing config", "component", "connection", "reason", reason)
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
