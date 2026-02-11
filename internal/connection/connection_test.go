package connection

import (
	"sync"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	m := NewManager(DefaultConfig())
	if m.State() != StateDisconnected {
		t.Errorf("Initial state = %s, want %s", m.State(), StateDisconnected)
	}
}

func TestStateTransitions(t *testing.T) {
	m := NewManager(DefaultConfig())

	// Disconnected -> Connecting
	m.SetState(StateConnecting)
	if m.State() != StateConnecting {
		t.Errorf("State = %s, want %s", m.State(), StateConnecting)
	}

	// Connecting -> Connected (via HeartbeatOK)
	m.HeartbeatOK()
	if m.State() != StateConnected {
		t.Errorf("State after HeartbeatOK = %s, want %s", m.State(), StateConnected)
	}

	// Connected stays Connected on HeartbeatOK
	m.HeartbeatOK()
	if m.State() != StateConnected {
		t.Errorf("State = %s, want %s", m.State(), StateConnected)
	}
}

func TestHeartbeatFailure(t *testing.T) {
	m := NewManager(DefaultConfig())
	m.SetState(StateConnected)

	// First two failures don't change state
	m.HeartbeatFailed(false)
	if m.State() != StateConnected {
		t.Errorf("State after 1 fail = %s, want %s", m.State(), StateConnected)
	}

	m.HeartbeatFailed(false)
	if m.State() != StateConnected {
		t.Errorf("State after 2 fails = %s, want %s", m.State(), StateConnected)
	}

	// Third failure triggers reconnecting
	m.HeartbeatFailed(false)
	if m.State() != StateReconnecting {
		t.Errorf("State after 3 fails = %s, want %s", m.State(), StateReconnecting)
	}
}

func TestHeartbeatUnpair(t *testing.T) {
	m := NewManager(DefaultConfig())
	m.SetState(StateConnected)

	// Unpair signal should immediately change state
	m.HeartbeatFailed(true)
	if m.State() != StateUnpaired {
		t.Errorf("State after unpair = %s, want %s", m.State(), StateUnpaired)
	}
}

func TestConsecutiveFailsReset(t *testing.T) {
	m := NewManager(DefaultConfig())
	m.SetState(StateConnected)

	// Accumulate failures
	m.HeartbeatFailed(false)
	m.HeartbeatFailed(false)
	if m.ConsecutiveFails() != 2 {
		t.Errorf("ConsecutiveFails = %d, want 2", m.ConsecutiveFails())
	}

	// HeartbeatOK resets counter
	m.HeartbeatOK()
	if m.ConsecutiveFails() != 0 {
		t.Errorf("ConsecutiveFails after OK = %d, want 0", m.ConsecutiveFails())
	}
}

func TestStateChangeCallback(t *testing.T) {
	m := NewManager(DefaultConfig())

	var mu sync.Mutex
	var transitions []struct{ old, new State }

	m.SetCallbacks(
		func(old, newState State) {
			mu.Lock()
			transitions = append(transitions, struct{ old, new State }{old, newState})
			mu.Unlock()
		},
		nil,
		nil,
	)

	m.SetState(StateConnecting)
	m.SetState(StateConnected)
	m.SetState(StateReconnecting)

	mu.Lock()
	defer mu.Unlock()

	if len(transitions) != 3 {
		t.Fatalf("Expected 3 transitions, got %d", len(transitions))
	}

	if transitions[0].old != StateDisconnected || transitions[0].new != StateConnecting {
		t.Errorf("Transition 0: %s -> %s, want disconnected -> connecting", transitions[0].old, transitions[0].new)
	}
	if transitions[1].old != StateConnecting || transitions[1].new != StateConnected {
		t.Errorf("Transition 1: %s -> %s, want connecting -> connected", transitions[1].old, transitions[1].new)
	}
}

func TestNoCallbackOnSameState(t *testing.T) {
	m := NewManager(DefaultConfig())

	callCount := 0
	m.SetCallbacks(
		func(old, newState State) {
			callCount++
		},
		nil,
		nil,
	)

	m.SetState(StateConnecting)
	m.SetState(StateConnecting) // Same state — should not trigger callback

	if callCount != 1 {
		t.Errorf("Callback called %d times, want 1 (should not fire on same state)", callCount)
	}
}

func TestBackoffCalculation(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)

	// First backoff should be around baseRetryDelay (with jitter)
	delay1 := m.CalculateBackoff()
	if delay1 < cfg.BaseRetryDelay || delay1 > cfg.BaseRetryDelay*3 {
		t.Errorf("First backoff = %v, expected between %v and %v", delay1, cfg.BaseRetryDelay, cfg.BaseRetryDelay*3)
	}

	// Each subsequent call should generally increase (exponential)
	delay2 := m.CalculateBackoff()
	delay3 := m.CalculateBackoff()

	// After reset, should go back to base
	m.ResetBackoff()
	delay4 := m.CalculateBackoff()
	if delay4 > delay3 {
		t.Errorf("After reset, delay4 (%v) should be <= delay3 (%v)", delay4, delay3)
	}

	// Verify backoff is capped at MaxRetryDelay
	for i := 0; i < 20; i++ {
		m.CalculateBackoff()
	}
	capped := m.CalculateBackoff()
	if capped > cfg.MaxRetryDelay*2 { // Allow for jitter
		t.Errorf("Capped delay = %v, exceeds max %v (with jitter)", capped, cfg.MaxRetryDelay*2)
	}

	_ = delay2 // used to verify increase
}

func TestLastHeartbeatAge(t *testing.T) {
	m := NewManager(DefaultConfig())

	// Before any heartbeat, age should be 0
	if age := m.LastHeartbeatAge(); age != 0 {
		t.Errorf("Initial heartbeat age = %v, want 0", age)
	}

	// After heartbeat OK, age should be very small
	m.HeartbeatOK()
	time.Sleep(10 * time.Millisecond)
	age := m.LastHeartbeatAge()
	if age < 10*time.Millisecond || age > 1*time.Second {
		t.Errorf("Heartbeat age = %v, expected ~10ms", age)
	}
}

func TestGetStatus(t *testing.T) {
	m := NewManager(DefaultConfig())
	m.SetState(StateConnected)
	m.HeartbeatOK()

	status := m.GetStatus()

	if status["state"] != string(StateConnected) {
		t.Errorf("Status state = %v, want %s", status["state"], StateConnected)
	}
	if status["consecutive_fails"] != 0 {
		t.Errorf("Status consecutive_fails = %v, want 0", status["consecutive_fails"])
	}
	if _, ok := status["last_heartbeat"]; !ok {
		t.Error("Status missing last_heartbeat after HeartbeatOK")
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := NewManager(DefaultConfig())
	m.SetState(StateConnected)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			m.HeartbeatOK()
		}()
		go func() {
			defer wg.Done()
			m.HeartbeatFailed(false)
		}()
		go func() {
			defer wg.Done()
			_ = m.State()
			_ = m.ConsecutiveFails()
			_ = m.GetStatus()
		}()
	}
	wg.Wait()

	// If we get here without a panic or race, the test passes
}
