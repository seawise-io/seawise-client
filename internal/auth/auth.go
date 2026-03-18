package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
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

// cliSessionFile returns the path to the CLI session file.
func cliSessionFile() string {
	return filepath.Join(paths.DataDir(), "cli-session")
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

// cliSessionHashFile returns the path to the session token hash.
func cliSessionHashFile() string {
	return filepath.Join(paths.DataDir(), "cli-session-hash")
}

// hasValidCLISession checks if there's a valid CLI session.
func hasValidCLISession() bool {
	data, err := os.ReadFile(cliSessionFile())
	if err != nil {
		return false
	}

	parts := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(parts) != 2 {
		return false
	}

	token := parts[0]
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}

	if time.Now().Unix() >= expiry {
		return false
	}

	storedHash, err := os.ReadFile(cliSessionHashFile())
	if err != nil {
		return false
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	return tokenHash == strings.TrimSpace(string(storedHash))
}

// createCLISession creates a new CLI session.
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

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	if err := os.WriteFile(cliSessionHashFile(), []byte(tokenHash), 0600); err != nil {
		return fmt.Errorf("write session hash file: %w", err)
	}

	return nil
}

// refreshCLISession extends the CLI session expiry.
func refreshCLISession() {
	data, err := os.ReadFile(cliSessionFile())
	if err != nil {
		return
	}

	parts := strings.Split(strings.TrimSpace(string(data)), ":")
	if len(parts) != 2 {
		return
	}

	expiry := time.Now().Add(cliSessionDuration).Unix()
	content := fmt.Sprintf("%s:%d", parts[0], expiry)
	if err := os.WriteFile(cliSessionFile(), []byte(content), 0600); err != nil { // #nosec G703
		log.Printf("[auth] Warning: failed to refresh CLI session: %v", err)
	}
}

// HashAndSavePassword hashes a password with bcrypt and saves it.
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

// ClearCLISession removes the CLI session and hash files.
func ClearCLISession() error {
	for _, f := range []string{cliSessionFile(), cliSessionHashFile()} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear CLI session file %s: %w", f, err)
		}
	}
	return nil
}

// PromptPassword prompts the user for a password without echoing.
func PromptPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	if term.IsTerminal(int(syscall.Stdin)) {
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // Add newline after password input
		if err != nil {
			return "", fmt.Errorf("read password from terminal: %w", err)
		}
		return string(password), nil
	}

	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimSpace(password), nil
}

// RequireAuth prompts for password if one is set and there's no valid session.
func RequireAuth() {
	if !IsPasswordSet() {
		return
	}

	if hasValidCLISession() {
		refreshCLISession()
		return
	}

	password, err := PromptPassword("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if !VerifyPassword(password) {
		fmt.Fprintln(os.Stderr, "Error: Incorrect password")
		os.Exit(1)
	}

	if err := createCLISession(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not create session: %v\n", err)
	}
}
