package main

import (
	"log/slog"
	"os"
	"strconv"

	"github.com/seawise/client/cmd/seawise/cmd"
	"github.com/seawise/client/cmd/seawise/server"
	"github.com/seawise/client/internal/constants"
)

func main() {
	if len(os.Args) == 1 {
		port := constants.DefaultWebPort
		if envPort := os.Getenv("SEAWISE_PORT"); envPort != "" {
			if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
				port = p
			} else {
				slog.Warn("Invalid SEAWISE_PORT, using default", "component", "main", "value", envPort, "default_port", port)
			}
		}
		server.Run(port)
		return
	}

	cmd.Execute()
}
