package main

import (
	"math"
	"runtime/debug"
	"testing"
)

func TestMemoryLimitDefault(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prev)
	debug.SetMemoryLimit(math.MaxInt64)
	if got := applyMemoryLimit(func(string) string { return "" }); got != DefaultMemoryLimit {
		t.Fatalf("limit = %d", got)
	}
	debug.SetMemoryLimit(math.MaxInt64)
	if got := applyMemoryLimit(func(k string) string { return map[string]string{"GOMEMLIMIT": "200MiB"}[k] }); got != math.MaxInt64 {
		t.Fatalf("GOMEMLIMIT from the environment overridden: %d", got)
	}
}
