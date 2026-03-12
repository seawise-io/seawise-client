package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/spf13/cobra"
)

var unpairForce bool

var unpairCmd = &cobra.Command{
	Use:   "unpair",
	Short: "Disconnect this client from SeaWise",
	Long:  `Removes the pairing configuration and disconnects this client from your SeaWise account.`,
	Run: func(cmd *cobra.Command, args []string) {
		runUnpair()
	},
}

func init() {
	unpairCmd.Flags().BoolVarP(&unpairForce, "force", "f", false, "Skip confirmation prompt")
	rootCmd.AddCommand(unpairCmd)
}

func runUnpair() {
	cfg, err := config.Load()
	if err != nil || cfg.ServerID == "" {
		fmt.Println("This client is not paired.")
		return
	}

	if !unpairForce {
		fmt.Println("┌─────────────────────────────────────────────────────────────┐")
		fmt.Println("│                    Unpair Client                            │")
		fmt.Println("├─────────────────────────────────────────────────────────────┤")
		fmt.Println("│                                                             │")
		fmt.Printf("│  Server:  %-48s │\n", cfg.ServerName)
		fmt.Printf("│  Account: %-48s │\n", cfg.UserEmail)
		fmt.Println("│                                                             │")
		fmt.Println("│  This will:                                                 │")
		fmt.Println("│  • Remove all service tunnels                               │")
		fmt.Println("│  • Delete local configuration                               │")
		fmt.Println("│  • Disconnect from SeaWise                                  │")
		fmt.Println("│                                                             │")
		fmt.Println("└─────────────────────────────────────────────────────────────┘")
		fmt.Println()
		fmt.Print("Are you sure you want to unpair? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("❌ Failed to read input: %v\n", err)
			os.Exit(1)
		}
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "y" && response != "yes" {
			fmt.Println("Cancelled.")
			return
		}
	}

	fmt.Println("Unpairing...")

	// Notify API to remove the server from the dashboard
	apiClient, apiErr := api.New(config.GetAPIURL(cfg))
	if apiErr != nil {
		fmt.Printf("⚠️  Warning: Invalid API URL: %v\n", apiErr)
	} else {
		apiClient.SetFRPToken(cfg.FRPToken)
		if err := apiClient.DeleteServer(cfg.ServerID); err != nil {
			fmt.Printf("⚠️  Warning: Failed to notify server: %v\n", err)
		}
	}

	if err := config.Delete(); err != nil {
		fmt.Printf("⚠️  Warning: Failed to delete config: %v\n", err)
	}

	fmt.Println()
	fmt.Println("✅ \033[1;32mSuccessfully unpaired!\033[0m")
	fmt.Println()
	fmt.Println("Run 'seawise pair' to connect to a SeaWise account again.")
}
