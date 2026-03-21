package cmd

import (
	"fmt"
	"os"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/localclient"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current connection status",
	Long:  `Displays the current pairing status, server information, and app count.`,
	Run: func(cmd *cobra.Command, args []string) {
		runStatus()
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus() {
	// Try local server first — gets live FRP + connection state
	lc := localclient.NewDefault()
	if lc.IsRunning() {
		status, err := lc.Status()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		printStatusFromServer(status)
		return
	}

	// Fallback: read config + query cloud API
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

	apiClient, err := api.New(cfg.APIURL)
	if err != nil {
		fmt.Printf("Error: Invalid API URL: %v\n", err)
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
	fmt.Println("│  Status: \033[1;32mPaired\033[0m (server not running)                     │")
	fmt.Println("│                                                             │")
	fmt.Printf("│  Server:   \033[1;37m%-47s\033[0m │\n", cfg.ServerName)
	fmt.Printf("│  Account:  \033[1;37m%-47s\033[0m │\n", cfg.UserEmail)
	fmt.Printf("│  Apps:     \033[1;37m%-47d\033[0m │\n", serviceCount)
	fmt.Println("│                                                             │")
	fmt.Printf("│  Server ID: %-46s │\n", cfg.ServerID)
	fmt.Println("└─────────────────────────────────────────────────────────────┘")

	fmt.Println()
	fmt.Println("Run 'seawise serve' to start the server")
}

func printStatusFromServer(status map[string]interface{}) {
	paired, _ := status["paired"].(bool)

	if !paired {
		fmt.Println("┌─────────────────────────────────────────┐")
		fmt.Println("│           SeaWise Status                │")
		fmt.Println("├─────────────────────────────────────────┤")
		fmt.Println("│  Status: \033[1;31mNot Paired\033[0m                    │")
		fmt.Println("│  Server: \033[1;32mRunning\033[0m                       │")
		fmt.Println("│                                         │")
		fmt.Println("│  Open the web UI to pair this server    │")
		fmt.Println("└─────────────────────────────────────────┘")
		return
	}

	serverName, _ := status["server_name"].(string)
	userEmail, _ := status["user_email"].(string)
	serviceCount := 0
	if sc, ok := status["service_count"].(float64); ok {
		serviceCount = int(sc)
	}
	serverID, _ := status["server_id"].(string)

	frpState := "unknown"
	if fs, ok := status["frp_state"].(string); ok {
		frpState = fs
	}
	frpRunning, _ := status["frp_running"].(bool)

	connState := ""
	if cs, ok := status["connection_state"].(string); ok {
		connState = cs
	}

	statusText := "\033[1;32mConnected\033[0m"
	if !frpRunning {
		statusText = "\033[1;33mPaired (tunnel down)\033[0m"
	}
	if connState == "superseded" {
		statusText = "\033[1;33mSuperseded\033[0m"
	}

	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    SeaWise Status                           │")
	fmt.Println("├─────────────────────────────────────────────────────────────┤")
	fmt.Printf("│  Status:  %-49s │\n", statusText)
	fmt.Println("│                                                             │")
	fmt.Printf("│  Server:   \033[1;37m%-47s\033[0m │\n", serverName)
	fmt.Printf("│  Account:  \033[1;37m%-47s\033[0m │\n", userEmail)
	fmt.Printf("│  Apps:     \033[1;37m%-47d\033[0m │\n", serviceCount)
	fmt.Printf("│  Tunnel:   %-48s │\n", frpState)
	if connState != "" {
		fmt.Printf("│  Conn:     %-48s │\n", connState)
	}
	fmt.Println("│                                                             │")
	fmt.Printf("│  Server ID: %-46s │\n", serverID)
	fmt.Println("└─────────────────────────────────────────────────────────────┘")

	if serviceCount > 0 {
		fmt.Println()
		fmt.Println("Run 'seawise services list' to see your apps")
	} else {
		fmt.Println()
		fmt.Println("Run 'seawise services add' to add your first app")
	}
}
