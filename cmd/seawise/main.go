package main

import (
	"os"

	"github.com/seawise/client/cmd/seawise/cmd"
	"github.com/seawise/client/cmd/seawise/server"
	"github.com/seawise/client/internal/constants"
)

func main() {
	// If no arguments provided, run the server (backwards compatible)
	if len(os.Args) == 1 {
		server.Run(constants.DefaultWebPort)
		return
	}

	// Otherwise, use cobra CLI
	cmd.Execute()
}
