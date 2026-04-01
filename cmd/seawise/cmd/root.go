package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "seawise",
	Short: "Seawise.io client - expose local services securely",
	Long: `Seawise.io client allows you to expose local services through secure tunnels.

Starts the web UI and FRP tunnel service. Manage services, pair servers,
and configure settings through the web interface.`,
	// Default command is serve — run without subcommands to start
	Run: serveCmd.Run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
}
