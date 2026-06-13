// Package password implements configurable password strength validation and
// history-based reuse prevention (bcrypt comparison against N most recent hashes).
package password

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"goauth/services/identity-service/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// Policy holds configurable password strength rules.
type Policy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	HistoryCount     int
}

// LoadFromConfig builds a Policy from the service config with sensible defaults.
//
// Call chain: wire → LoadFromConfig → config.Config fields
func LoadFromConfig(cfg config.Config) Policy {
	minLen := cfg.PasswordMinLength
	if minLen <= 0 {
		minLen = 8
	}
	historyCount := cfg.PasswordHistoryCount
	if historyCount < 0 {
		historyCount = 0
	}
	return Policy{
		MinLength:        minLen,
		RequireUppercase: cfg.PasswordRequireUpper,
		RequireLowercase: cfg.PasswordRequireLower,
		RequireDigit:     cfg.PasswordRequireDigit,
		RequireSpecial:   cfg.PasswordRequireSpecial,
		HistoryCount:     historyCount,
	}
}

// Validate checks the password against all configured rules.
// Returns nil if valid, or a combined error listing all violations.
//
// Call chain: password-change handler → Validate → unicode checks
func (p Policy) Validate(password string) error {
	var violations []string

	if len(password) < p.MinLength {
		violations = append(violations, fmt.Sprintf("minimum length is %d", p.MinLength))
	}

	if p.RequireUppercase || p.RequireLowercase || p.RequireDigit || p.RequireSpecial {
		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, r := range password {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				hasSpecial = true
			}
		}
		if p.RequireUppercase && !hasUpper {
			violations = append(violations, "must contain at least one uppercase letter")
		}
		if p.RequireLowercase && !hasLower {
			violations = append(violations, "must contain at least one lowercase letter")
		}
		if p.RequireDigit && !hasDigit {
			violations = append(violations, "must contain at least one digit")
		}
		if p.RequireSpecial && !hasSpecial {
			violations = append(violations, "must contain at least one special character")
		}
	}

	if len(violations) == 0 {
		return nil
	}
	return errors.New("password policy violation: " + strings.Join(violations, "; "))
}

// CheckHistory returns an error if the new password matches any of the
// provided bcrypt hashes (most recent first).
//
// Call chain: password-change handler → CheckHistory → bcrypt.CompareHashAndPassword
func (p Policy) CheckHistory(newPassword string, hashes []string) error {
	limit := p.HistoryCount
	if limit <= 0 || len(hashes) == 0 {
		return nil
	}
	if limit > len(hashes) {
		limit = len(hashes)
	}
	for _, h := range hashes[:limit] {
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte(newPassword)); err == nil {
			return errors.New("password was used recently and cannot be reused")
		}
	}
	return nil
}
