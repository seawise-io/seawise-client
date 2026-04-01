// Package auth provides password management for the Seawise.io client.
// Passwords are hashed with bcrypt and stored on disk.
// Web UI sessions are managed by the server package, not here.
package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/seawise/client/internal/constants"
	"github.com/seawise/client/internal/paths"
	"golang.org/x/crypto/bcrypt"
)

// PasswordFile returns the path to the password hash file
func PasswordFile() string {
	return filepath.Join(paths.DataDir(), "password.hash")
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
