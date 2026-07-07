// Package utils provides shared helper utilities used across the VibeNet backend.
package utils

import (
	"fmt"
	"os"
)

// GetEnv retrieves the value of an environment variable.
// If the variable is unset or empty, it returns the provided fallback default.
func GetEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// RequireEnv retrieves the value of a required environment variable.
// It returns an error when the variable is unset or empty.
func RequireEnv(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("required environment variable %q is not set", key)
	}
	return value, nil
}
