package cmd

import (
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
	serveCmd.Flags().IntVarP(&servePort, "port", "p", constants.DefaultWebPort, "Port for the web UI")
	rootCmd.AddCommand(serveCmd)
}
