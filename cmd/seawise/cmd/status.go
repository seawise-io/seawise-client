package cmd

import (
	"fmt"
	"os"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current connection status",
	Long:  `Displays the current pairing status, server information, and service count.`,
	Run: func(cmd *cobra.Command, args []string) {
		runStatus()
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus() {
	cfg, err := config.Load()
	if err != nil || cfg.ServerID == "" {
		fmt.Println("┌─────────────────────────────────────────┐")
		fmt.Println("│           SeaWise Status                │")
		fmt.Println("├─────────────────────────────────────────┤")
		fmt.Println("│  Status: \033[1;31mNot Paired\033[0m                    │")
		fmt.Println("│                                         │")
		fmt.Println("│  Run 'seawise pair' to get started      │")
		fmt.Println("└─────────────────────────────────────────┘")
		return
	}

	// Get service count from API
	apiClient, err := api.New(cfg.APIURL)
	if err != nil {
		fmt.Printf("❌ Invalid API URL: %v\n", err)
		os.Exit(1)
	}
	apiClient.SetFRPToken(cfg.FRPToken)
	services, err := apiClient.ListServices(cfg.ServerID)
	serviceCount := 0
	if err == nil {
		serviceCount = len(services)
	}

	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    SeaWise Status                           │")
	fmt.Println("├─────────────────────────────────────────────────────────────┤")
	fmt.Println("│  Status: \033[1;32mPaired\033[0m                                          │")
	fmt.Println("│                                                             │")
	fmt.Printf("│  Server:   \033[1;37m%-47s\033[0m │\n", cfg.ServerName)
	fmt.Printf("│  Account:  \033[1;37m%-47s\033[0m │\n", cfg.UserEmail)
	fmt.Printf("│  Services: \033[1;37m%-47d\033[0m │\n", serviceCount)
	fmt.Println("│                                                             │")
	fmt.Printf("│  Server ID: %-46s │\n", cfg.ServerID)
	fmt.Println("└─────────────────────────────────────────────────────────────┘")

	if serviceCount > 0 {
		fmt.Println()
		fmt.Println("Run 'seawise services list' to see your services")
	} else {
		fmt.Println()
		fmt.Println("Run 'seawise services add' to add your first service")
	}
}
