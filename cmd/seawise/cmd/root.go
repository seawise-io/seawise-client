package cmd

import (
	"fmt"
	"os"

	"github.com/seawise/client/internal/auth"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "seawise",
	Short: "SeaWise client - expose local services securely",
	Long: `SeaWise client allows you to expose local services through secure tunnels.

Run without arguments to start the web UI and FRP tunnel service.
Use subcommands for CLI-based management.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip auth for serve command (web UI handles its own auth)
		// and for password management commands
		name := cmd.Name()
		if name == "serve" || name == "seawise" {
			return
		}
		// Skip auth for password subcommands
		if cmd.Parent() != nil && cmd.Parent().Name() == "password" {
			return
		}
		if name == "password" {
			return
		}
		// Require password if one is set
		auth.RequireAuth()
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags can be added here
}
