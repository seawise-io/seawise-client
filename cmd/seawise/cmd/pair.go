package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/constants"
	"github.com/spf13/cobra"
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Pair this client with your SeaWise account",
	Long: `Initiates the pairing process to connect this client to your SeaWise account.

This will generate a pairing link that you can open in your browser to complete the connection.`,
	Run: func(cmd *cobra.Command, args []string) {
		runPair()
	},
}

func init() {
	rootCmd.AddCommand(pairCmd)
}

func runPair() {
	reader := bufio.NewReader(os.Stdin)

	// Check if already paired
	cfg, err := config.Load()
	if err == nil && cfg.ServerID != "" {
		fmt.Println("⚠️  This client is already paired.")
		fmt.Printf("   Server: %s\n", cfg.ServerName)
		fmt.Printf("   Account: %s\n", cfg.UserEmail)
		fmt.Println()
		fmt.Print("Do you want to unpair and pair again? [y/N]: ")

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

		// Unpair first
		fmt.Println("Unpairing...")
		if err := config.Delete(); err != nil {
			fmt.Printf("⚠️  Warning: Failed to delete old config: %v\n", err)
		}
	}

	// Get server name
	fmt.Print("Enter a name for this server: ")
	serverName, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("❌ Failed to read input: %v\n", err)
		os.Exit(1)
	}
	serverName = strings.TrimSpace(serverName)

	if serverName == "" {
		hostname, hostnameErr := os.Hostname()
		if hostnameErr == nil && hostname != "" {
			serverName = hostname
		} else {
			serverName = "My Server"
		}
		fmt.Printf("Using default name: %s\n", serverName)
	}

	// Initialize API client
	apiURL := config.GetAPIURL(nil)
	apiClient, err := api.New(apiURL)
	if err != nil {
		fmt.Printf("❌ Invalid API URL: %v\n", err)
		os.Exit(1)
	}

	// Get pairing codes (OAuth Device Flow: user_code + device_code)
	fmt.Println()
	fmt.Println("🔗 Requesting pairing code...")

	codes, err := apiClient.InitPairing(serverName)
	if err != nil {
		fmt.Printf("❌ Failed to get pairing code: %v\n", err)
		os.Exit(1)
	}

	// Generate the pairing URL with user_code (shown to user)
	pairingURL := fmt.Sprintf("%s/connect?code=%s", config.GetWebURL(), codes.UserCode)

	// Display the pairing info
	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    SeaWise Pairing                          │")
	fmt.Println("├─────────────────────────────────────────────────────────────┤")
	fmt.Println("│                                                             │")
	fmt.Println("│  Open this URL in your browser to connect:                  │")
	fmt.Println("│                                                             │")
	fmt.Printf("│  \033[1;36m%s\033[0m\n", pairingURL)
	fmt.Println("│                                                             │")
	fmt.Printf("│  Code: \033[1;33m%s\033[0m                                              │\n", codes.UserCode)
	fmt.Printf("│  Expires: %s                                   │\n", codes.ExpiresAt.Format("15:04:05"))
	fmt.Println("│                                                             │")
	fmt.Println("│  Waiting for you to click 'Connect' in the browser...       │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Poll for pairing completion using device_code (kept secret)
	ticker := time.NewTicker(constants.PairPollInterval)
	defer ticker.Stop()

	timeout := time.After(constants.PairTimeout)
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	spinIdx := 0

	for {
		select {
		case <-timeout:
			fmt.Println("\n❌ Pairing timed out. Please try again.")
			os.Exit(1)

		case <-ticker.C:
			// Show spinner
			fmt.Printf("\r%s Waiting for connection...", spinner[spinIdx])
			spinIdx = (spinIdx + 1) % len(spinner)

			// Check if pairing completed using device_code (not user_code)
			result, err := apiClient.CompletePairing(codes.DeviceCode)
			if err != nil {
				// "not_approved" is expected during polling — only log unexpected errors
				if !strings.Contains(err.Error(), "not yet approved") && !strings.Contains(err.Error(), "pending") {
					fmt.Printf("\r⚠️  Poll error: %v (retrying...)\n", err)
				}
				continue
			}

			// Pairing successful!
			fmt.Println("\r                                        ") // Clear spinner line
			fmt.Println()
			fmt.Println("✅ \033[1;32mPairing successful!\033[0m")
			fmt.Println()
			fmt.Printf("   Server ID: %s\n", result.Data.ServerID)
			fmt.Printf("   Server Name: %s\n", result.Data.ServerName)
			fmt.Printf("   Account: %s\n", result.Data.UserEmail)
			fmt.Println()

			// Save config
			newCfg := &config.Config{
				ServerID:      result.Data.ServerID,
				ServerName:    result.Data.ServerName,
				FRPToken:      result.Data.FRPToken,
				FRPServerAddr: result.Data.FRPServerAddr,
				FRPServerPort: result.Data.FRPServerPort,
				FRPUseTLS:     result.Data.FRPUseTLS,
				APIURL:        apiURL,
				UserID:        result.Data.UserID,
				UserEmail:     result.Data.UserEmail,
			}

			if err := newCfg.Save(); err != nil {
				fmt.Printf("❌ Failed to save pairing config: %v\n", err)
				fmt.Println("Pairing completed on the server but could not be saved locally.")
				fmt.Println("Please try again with: seawise pair")
				os.Exit(1)
			}

			fmt.Println("🚀 You can now add services with: seawise services add")
			fmt.Println("   Or start the web UI with: seawise serve")
			return
		}
	}
}
