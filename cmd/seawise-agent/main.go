// Command seawise-agent runs the client v2 runtime. It keeps its state in
// <datadir>/v2 and reads existing client files without modifying them.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/seawise/client/internal/agent"
	"github.com/seawise/client/internal/paths"
	"github.com/seawise/client/internal/store"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	st, err := store.Open(paths.DataDir(), time.Now)
	if err != nil {
		log.Error("open state", "error", err)
		os.Exit(1)
	}
	for _, w := range st.Warnings {
		log.Warn(w)
	}

	cfg := agent.Config{
		Store:         st,
		FRPCPath:      envOr("SEAWISE_FRPC_PATH", "/app/frpc"),
		TrustedCAFile: envOr("SEAWISE_TRUSTED_CA_FILE", agent.DefaultTrustedCA),
		Logger:        log,
	}
	if v := os.Getenv("SEAWISE_FRPC_ADMIN_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			log.Error("invalid SEAWISE_FRPC_ADMIN_PORT", "value", v)
			os.Exit(1)
		}
		cfg.AdminPort = p
	}
	a, err := agent.New(cfg)
	if err != nil {
		log.Error("start agent", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
