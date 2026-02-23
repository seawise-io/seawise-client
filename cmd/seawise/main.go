package main

import (
	"os"
	"strconv"

	"github.com/seawise/client/cmd/seawise/cmd"
	"github.com/seawise/client/cmd/seawise/server"
	"github.com/seawise/client/internal/constants"
)

func main() {
	// If no arguments provided, run the server (backwards compatible)
	if len(os.Args) == 1 {
		port := constants.DefaultWebPort
		if envPort := os.Getenv("SEAWISE_PORT"); envPort != "" {
			if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
				port = p
			}
		}
		server.Run(port)
		return
	}

	// Otherwise, use cobra CLI
	cmd.Execute()
}
