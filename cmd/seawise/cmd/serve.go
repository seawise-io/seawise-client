package cmd

import (
	"log"
	"os"
	"strconv"

	"github.com/seawise/client/cmd/seawise/server"
	"github.com/seawise/client/internal/constants"
	"github.com/spf13/cobra"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the SeaWise client server with web UI",
	Long:  `Starts the SeaWise client server which provides a web UI for managing services and maintains the FRP tunnel connection.`,
	Run: func(cmd *cobra.Command, args []string) {
		server.Run(servePort)
	},
}

func init() {
	defaultPort := constants.DefaultWebPort
	if envPort := os.Getenv("SEAWISE_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
			defaultPort = p
		} else {
			log.Printf("[WARN] Invalid SEAWISE_PORT=%q (must be 1-65535), using default %d", envPort, defaultPort) // #nosec G706 -- envPort quoted with %q
		}
	}
	serveCmd.Flags().IntVarP(&servePort, "port", "p", defaultPort, "Port for the web UI (env: SEAWISE_PORT)")
	rootCmd.AddCommand(serveCmd)
}
