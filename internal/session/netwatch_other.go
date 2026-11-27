//go:build !linux

package session

import (
	"context"
	"log/slog"
)

func watchNetlink(context.Context, chan<- struct{}, *slog.Logger) bool { return false }
