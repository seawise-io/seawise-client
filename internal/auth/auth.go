package auth

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/paths"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const (
	// CLI session expires after 1 hour of inactivity
	cliSessionDuration = 1 * time.Hour
)

// PasswordFile returns the path to the password hash file
func PasswordFile() string {
	return filepath.Join(paths.DataDir(), "password.hash")
}

// cliSessionFile returns the path to the CLI session file (in /tmp so it's cleared on reboot)
func cliSessionFile() string {
	return fmt.Sprintf("/tmp/seawise-cli-session-%d", os.Getuid())
}

// IsPasswordSet returns true if a password has been configured
func IsPasswordSet() bool {
	data, err := os.ReadFile(PasswordFile())
	return err == nil && len(data) > 0
}

// VerifyPassword checks if the given password matches the stored hash
func VerifyPassword(password string) bool {
	data, err := os.ReadFile(PasswordFile())
	if err != nil || len(data) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(data, []byte(password)) == nil
}

// hasValidCLISession checks if there's a valid CLI session
func hasValidCLISession() bool {
	data, err := os.ReadFile(cliSessionFile())
	if err != nil {
		return false
	}

	// Format: token:expiry_unix
	parts := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(parts) != 2 {
		return false
	}

	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}

	return time.Now().Unix() < expiry
}

// createCLISession creates a new CLI session
func createCLISession() error {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	expiry := time.Now().Add(cliSessionDuration).Unix()

	content := fmt.Sprintf("%s:%d", token, expiry)
	if err := os.WriteFile(cliSessionFile(), []byte(content), 0600); err != nil {
		return fmt.Errorf("write session file: %w", err)
	}
	return nil
}

// refreshCLISession extends the CLI session expiry
func refreshCLISession() {
	data, err := os.ReadFile(cliSessionFile())
	if err != nil {
		return
	}

	parts := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(parts) != 2 {
		return
	}

	// Keep the same token, update expiry
	expiry := time.Now().Add(cliSessionDuration).Unix()
	content := fmt.Sprintf("%s:%d", parts[0], expiry)
	if err := os.WriteFile(cliSessionFile(), []byte(content), 0600); err != nil {
		// Log but don't fail - session refresh is best-effort
		// Next CLI command will just re-authenticate
		log.Printf("[auth] Warning: failed to refresh CLI session: %v", err)
	}
}

// HashAndSavePassword hashes a password with bcrypt and saves it to the standard location.
// Returns the hash so callers can update in-memory state if needed.
func HashAndSavePassword(password string) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), constants.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	pwFile := PasswordFile()
	dir := filepath.Dir(pwFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create password directory: %w", err)
	}
	if err := os.WriteFile(pwFile, hash, 0600); err != nil {
		return nil, fmt.Errorf("write password file: %w", err)
	}
	return hash, nil
}

// ClearCLISession removes the CLI session (used when password is changed/removed)
// Returns nil if file doesn't exist or was successfully removed.
func ClearCLISession() error {
	err := os.Remove(cliSessionFile())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear CLI session: %w", err)
	}
	return nil
}

// PromptPassword prompts the user for a password without echoing
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// Try to read password without echo (works in real terminals)
	if term.IsTerminal(int(syscall.Stdin)) {
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // Add newline after password input
		if err != nil {
			return "", fmt.Errorf("read password from terminal: %w", err)
		}
		return string(password), nil
	}

	// Fallback for non-terminal input (e.g., pipes)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimSpace(password), nil
}

// RequireAuth checks if a password is set, and if so, verifies the user.
// Uses session caching so password isn't required every command.
// Exits the program on auth failure.
func RequireAuth() {
	if !IsPasswordSet() {
		return // No password set, allow access
	}

	// Check for valid CLI session
	if hasValidCLISession() {
		refreshCLISession() // Extend the session
		return
	}

	// No valid session, prompt for password
	password, err := PromptPassword("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if !VerifyPassword(password) {
		fmt.Fprintln(os.Stderr, "❌ Incorrect password")
		os.Exit(1)
	}

	// Create new session
	if err := createCLISession(); err != nil {
		// Non-fatal, just won't cache the session
		fmt.Fprintf(os.Stderr, "Warning: Could not create session: %v\n", err)
	}
}
