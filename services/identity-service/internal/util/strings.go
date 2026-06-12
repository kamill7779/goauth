// Package util provides shared helper functions used across the identity service.
package util

import "strings"

// DefaultString returns value if non-empty after trimming, otherwise returns fallback.
func DefaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
