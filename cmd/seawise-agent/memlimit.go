package main

import "runtime/debug"

// DefaultMemoryLimit is the soft heap limit applied unless GOMEMLIMIT is
// set. It sits below the busy memory budget so the collector works harder
// before the process grows past it.
const DefaultMemoryLimit = 64 << 20

// applyMemoryLimit sets DefaultMemoryLimit when getenv has no GOMEMLIMIT,
// and returns the limit in effect.
func applyMemoryLimit(getenv func(string) string) int64 {
	if getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(DefaultMemoryLimit)
	}
	return debug.SetMemoryLimit(-1)
}
