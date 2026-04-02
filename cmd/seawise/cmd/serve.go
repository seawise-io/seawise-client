package cmd

import (
	"log/slog"
	"os"
	"strconv"

	"github.com/seawise/client/cmd/seawise/server"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/validation"
	"github.com/spf13/cobra"
)

var servePort int

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Seawise.io client with web UI",
	Long:  `Starts the Seawise.io client which provides a web UI for managing services and maintains the tunnel connection.`,
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
			slog.Warn("Invalid SEAWISE_PORT, using default", "component", "main", "value", validation.SanitizeLogValue(envPort), "default_port", defaultPort)
		}
	}
	serveCmd.Flags().IntVarP(&servePort, "port", "p", defaultPort, "Port for the web UI (env: SEAWISE_PORT)")
	rootCmd.AddCommand(serveCmd)
}
