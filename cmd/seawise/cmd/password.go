package cmd

import (
	"fmt"
	"os"

	"github.com/seawise/client/internal/auth"
	"github.com/spf13/cobra"
)

var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Manage CLI/UI password protection",
	Long: `Set, change, or remove the password that protects the CLI and web UI.

The same password is used for both the CLI commands and the web interface.`,
}

var passwordSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set or change the password",
	Long:  `Set a new password or change the existing one.`,
	Run: func(cmd *cobra.Command, args []string) {
		runPasswordSet()
	},
}

var passwordRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove password protection",
	Long:  `Remove the password, allowing unrestricted access to CLI and web UI.`,
	Run: func(cmd *cobra.Command, args []string) {
		runPasswordRemove()
	},
}

var passwordStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check if password is set",
	Run: func(cmd *cobra.Command, args []string) {
		if auth.IsPasswordSet() {
			fmt.Println("Password protection is \033[1;32menabled\033[0m")
		} else {
			fmt.Println("Password protection is \033[1;31mdisabled\033[0m")
			fmt.Println("\nRun 'seawise password set' to enable password protection.")
		}
	},
}

func init() {
	passwordCmd.AddCommand(passwordSetCmd)
	passwordCmd.AddCommand(passwordRemoveCmd)
	passwordCmd.AddCommand(passwordStatusCmd)
	rootCmd.AddCommand(passwordCmd)
}

func runPasswordSet() {
	if auth.IsPasswordSet() {
		fmt.Println("A password is already set. Enter current password to change it.")
		currentPw, err := auth.PromptPassword("Current password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to read password: %v\n", err)
			os.Exit(1)
		}
		if !auth.VerifyPassword(currentPw) {
			fmt.Fprintln(os.Stderr, "Error: Incorrect password")
			os.Exit(1)
		}
		fmt.Println()
	}

	newPw, err := auth.PromptPassword("New password (min 8 chars): ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if len(newPw) < 8 {
		fmt.Fprintln(os.Stderr, "Error: Password must be at least 8 characters")
		os.Exit(1)
	}

	confirmPw, err := auth.PromptPassword("Confirm password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if newPw != confirmPw {
		fmt.Fprintln(os.Stderr, "Error: Passwords do not match")
		os.Exit(1)
	}

	if _, err := auth.HashAndSavePassword(newPw); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to save password: %v\n", err)
		os.Exit(1)
	}

	if err := auth.ClearCLISession(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to clear CLI session: %v\n", err)
	}

	fmt.Println()
	fmt.Println("\033[1;32mPassword set successfully!\033[0m")
	fmt.Println()
	fmt.Println("This password now protects:")
	fmt.Println("  • All CLI commands (seawise status, services, etc.)")
	fmt.Println("  • The web UI at http://localhost:8082")
}

func runPasswordRemove() {
	if !auth.IsPasswordSet() {
		fmt.Println("No password is currently set.")
		return
	}

	currentPw, err := auth.PromptPassword("Enter current password to remove: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if !auth.VerifyPassword(currentPw) {
		fmt.Fprintln(os.Stderr, "Error: Incorrect password")
		os.Exit(1)
	}

	if err := os.Remove(auth.PasswordFile()); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Failed to remove password: %v\n", err)
		os.Exit(1)
	}

	if err := auth.ClearCLISession(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to clear CLI session: %v\n", err)
	}

	fmt.Println()
	fmt.Println("\033[1;32mPassword removed.\033[0m")
	fmt.Println()
	fmt.Println("Warning: The CLI and web UI are now accessible without a password.")
}
