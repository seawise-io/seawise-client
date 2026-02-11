package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/seawise/client/internal/api"
	"github.com/seawise/client/internal/config"
	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/validation"
	"github.com/spf13/cobra"
)

var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Manage services",
	Long:  `Add, list, and remove services from this server.`,
}

var servicesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all services",
	Run: func(cmd *cobra.Command, args []string) {
		runServicesList()
	},
}

var servicesAddCmd = &cobra.Command{
	Use:   "add [name] [host] [port]",
	Short: "Add a new service",
	Long: `Add a new service to expose through SeaWise.

You can provide arguments directly or run interactively:
  seawise services add "My App" localhost 8080
  seawise services add  (interactive mode)`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 3 {
			// Non-interactive mode
			port, err := strconv.Atoi(args[2])
			if err != nil {
				fmt.Printf("❌ Invalid port: %s\n", args[2])
				os.Exit(1)
			}
			runServicesAdd(args[0], args[1], port)
		} else {
			// Interactive mode
			runServicesAddInteractive()
		}
	},
}

var servicesRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a service",
	Long: `Remove a service from this server.

  seawise services remove "My App"
  seawise services remove  (interactive mode)`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) >= 1 {
			runServicesRemove(args[0])
		} else {
			runServicesRemoveInteractive()
		}
	},
}

func init() {
	servicesCmd.AddCommand(servicesListCmd)
	servicesCmd.AddCommand(servicesAddCmd)
	servicesCmd.AddCommand(servicesRemoveCmd)
	rootCmd.AddCommand(servicesCmd)
}

func checkPaired() (*config.Config, *api.Client) {
	cfg, err := config.Load()
	if err != nil || cfg.ServerID == "" {
		fmt.Println("❌ Not paired. Run 'seawise pair' first.")
		os.Exit(1)
	}
	return cfg, api.New(cfg.APIURL)
}

func runServicesList() {
	cfg, apiClient := checkPaired()
	apiClient.SetFRPToken(cfg.FRPToken)

	services, err := apiClient.ListServices(cfg.ServerID)
	if err != nil {
		fmt.Printf("❌ Failed to list services: %v\n", err)
		os.Exit(1)
	}

	if len(services) == 0 {
		fmt.Println("┌─────────────────────────────────────────────────────────────┐")
		fmt.Println("│                    Services                                 │")
		fmt.Println("├─────────────────────────────────────────────────────────────┤")
		fmt.Println("│  No services configured yet.                                │")
		fmt.Println("│                                                             │")
		fmt.Println("│  Run 'seawise services add' to add your first service       │")
		fmt.Println("└─────────────────────────────────────────────────────────────┘")
		return
	}

	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                    Services                                 │")
	fmt.Println("├─────────────────────────────────────────────────────────────┤")

	for _, svc := range services {
		statusIcon := "🟢"
		if svc.Status != "online" {
			statusIcon = "🔴"
		}
		fmt.Printf("│  %s %-55s │\n", statusIcon, svc.Name)
		fmt.Printf("│     Host: %-48s │\n", fmt.Sprintf("%s:%d", svc.Host, svc.Port))
		fmt.Printf("│     URL:  %-48s │\n", fmt.Sprintf("https://%s.%s", svc.Subdomain, constants.DefaultSubdomainHost))
		fmt.Println("│                                                             │")
	}

	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Printf("\nTotal: %d service(s)\n", len(services))
}

func runServicesAdd(name, host string, port int) {
	// Validate inputs
	if !validation.IsValidServiceName(name) {
		fmt.Println("❌ Invalid service name (must be 1-100 characters)")
		os.Exit(1)
	}
	if !validation.IsValidHost(host) {
		fmt.Println("❌ Invalid host format (must be a valid hostname or IP)")
		os.Exit(1)
	}
	if !validation.IsValidPort(port) {
		fmt.Println("❌ Invalid port (must be 1-65535)")
		os.Exit(1)
	}

	cfg, apiClient := checkPaired()
	apiClient.SetFRPToken(cfg.FRPToken)

	fmt.Printf("Adding service '%s' (%s:%d)...\n", name, host, port)

	result, err := apiClient.RegisterService(cfg.ServerID, name, host, port)
	if err != nil {
		fmt.Printf("❌ Failed to add service: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("✅ \033[1;32mService added successfully!\033[0m")
	fmt.Println()
	fmt.Printf("   Name:      %s\n", name)
	fmt.Printf("   Target:    %s:%d\n", host, port)
	fmt.Printf("   Subdomain: %s\n", result.Subdomain)
	fmt.Printf("   URL:       https://%s.%s\n", result.Subdomain, constants.DefaultSubdomainHost)
	fmt.Println()
	fmt.Println("Note: Start 'seawise serve' to activate the tunnel")
}

func runServicesAddInteractive() {
	// Validate pairing early (exits if not paired).
	// runServicesAdd will load config again for the API call.
	checkPaired()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│           Add New Service               │")
	fmt.Println("└─────────────────────────────────────────┘")
	fmt.Println()

	// Get name
	fmt.Print("Service name: ")
	name, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("❌ Failed to read input: %v\n", err)
		os.Exit(1)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("❌ Name is required")
		os.Exit(1)
	}

	// Get host
	fmt.Print("Host [localhost]: ")
	host, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("❌ Failed to read input: %v\n", err)
		os.Exit(1)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	// Get port
	fmt.Print("Port: ")
	portStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("❌ Failed to read input: %v\n", err)
		os.Exit(1)
	}
	portStr = strings.TrimSpace(portStr)
	port, portErr := strconv.Atoi(portStr)
	if portErr != nil || port < 1 || port > 65535 {
		fmt.Println("❌ Invalid port number")
		os.Exit(1)
	}

	fmt.Println()
	runServicesAdd(name, host, port)
}

func runServicesRemove(name string) {
	cfg, apiClient := checkPaired()
	apiClient.SetFRPToken(cfg.FRPToken)

	// Find service by name
	services, err := apiClient.ListServices(cfg.ServerID)
	if err != nil {
		fmt.Printf("❌ Failed to list services: %v\n", err)
		os.Exit(1)
	}

	var serviceToRemove *api.Service
	for _, svc := range services {
		if strings.EqualFold(svc.Name, name) {
			serviceToRemove = &svc
			break
		}
	}

	if serviceToRemove == nil {
		fmt.Printf("❌ Service '%s' not found\n", name)
		os.Exit(1)
	}

	fmt.Printf("Removing service '%s'...\n", serviceToRemove.Name)

	err = apiClient.DeleteService(cfg.ServerID, serviceToRemove.ID)
	if err != nil {
		fmt.Printf("❌ Failed to remove service: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("✅ \033[1;32mService removed successfully!\033[0m")
}

func runServicesRemoveInteractive() {
	cfg, apiClient := checkPaired()
	apiClient.SetFRPToken(cfg.FRPToken)

	services, err := apiClient.ListServices(cfg.ServerID)
	if err != nil {
		fmt.Printf("❌ Failed to list services: %v\n", err)
		os.Exit(1)
	}

	if len(services) == 0 {
		fmt.Println("No services to remove.")
		return
	}

	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│           Remove Service                │")
	fmt.Println("└─────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("Select a service to remove:")
	fmt.Println()

	for i, svc := range services {
		fmt.Printf("  %d. %s (%s:%d)\n", i+1, svc.Name, svc.Host, svc.Port)
	}

	fmt.Println()
	fmt.Print("Enter number (or 'q' to cancel): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("❌ Failed to read input: %v\n", err)
		os.Exit(1)
	}
	input = strings.TrimSpace(input)

	if input == "q" || input == "Q" {
		fmt.Println("Cancelled.")
		return
	}

	num, numErr := strconv.Atoi(input)
	if numErr != nil || num < 1 || num > len(services) {
		fmt.Println("❌ Invalid selection")
		os.Exit(1)
	}

	selectedService := services[num-1]
	runServicesRemove(selectedService.Name)
}
