package cmd

import (
	"fmt"

	"github.com/seawise/client/internal/constants"
	"github.com/spf13/cobra"
)

// SEA-231: `seawise version` — quick way to check the running version without
// firing up the server or the browser. Matches how cloudflared, headscale,
// argocd, and every kubectl-shaped CLI expose their version.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the SeaWise client version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(constants.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	// Also make `--version` on the root command print the same value.
	rootCmd.Version = constants.Version
	rootCmd.SetVersionTemplate("{{.Version}}\n")
}
