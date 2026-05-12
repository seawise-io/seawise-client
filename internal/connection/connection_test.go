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

	// SEA-154: previously the next two delays were declared and discarded
	// without verification. Now: assert exponential growth — each delay's
	// minimum (delay/2 to account for jitter band) should exceed the prior
	// delay's minimum, so growth is real and not just jitter noise.
	delay2 := m.CalculateBackoff()
	delay3 := m.CalculateBackoff()
	if delay2 < delay1 {
		t.Errorf("delay2 (%v) < delay1 (%v) — backoff should not regress", delay2, delay1)
	}
	if delay3 < delay2 {
		t.Errorf("delay3 (%v) < delay2 (%v) — backoff should not regress", delay3, delay2)
	}
	// Floor of expected exponential growth: 2^attempt * base, no jitter.
	// Allow some slack because jitter is additive (0-100%) so the floor is the base
	// scaling factor alone.
	floor3 := time.Duration(float64(cfg.BaseRetryDelay) * 4) // 2^2 = 4
	if delay3 < floor3 {
		t.Errorf("delay3 (%v) below 2^2 base floor (%v) — exponential growth not happening", delay3, floor3)
	}

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

	const okCount = 100
	const failCount = 100

	var wg sync.WaitGroup
	for i := 0; i < okCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.HeartbeatOK()
		}()
	}
	for i := 0; i < failCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.HeartbeatFailed(false)
		}()
	}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Reads — must not panic or return malformed values
			_ = m.State()
			_ = m.ConsecutiveFails()
			_ = m.GetStatus()
		}()
	}
	wg.Wait()

	// SEA-154: previously the test asserted nothing — even if HeartbeatFailed
	// corrupted internal counters, the test would pass. Now we assert real
	// invariants: consecutive_fails must be non-negative and bounded by the
	// number of failure events; if the last event happened to be HeartbeatOK
	// we expect 0; otherwise <= failCount.
	fails := m.ConsecutiveFails()
	if fails < 0 {
		t.Errorf("ConsecutiveFails went negative: %d (mutex bug or counter underflow)", fails)
	}
	if fails > failCount {
		t.Errorf("ConsecutiveFails (%d) exceeds total failure events (%d) — counter incremented too far", fails, failCount)
	}
}
