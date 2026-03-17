package main

import (
	"log"
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
			} else {
				log.Printf("[WARN] Invalid SEAWISE_PORT=%q (must be 1-65535), using default %d", envPort, port) // #nosec G706 — envPort is from os.Getenv, not user input
			}
		}
		server.Run(port)
		return
	}

	// Otherwise, use cobra CLI
	cmd.Execute()
}
