// Package identity provides helpers for sanitising and validating user-facing
// identity fields. Every function is deterministic: the same input always
// produces the same output with no dependency on external state.
package identity

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUsernameTooShort = errors.New("username must be at least 3 characters")
	ErrUsernameInvalid  = errors.New("username may only contain a-z, 0-9, _ and -")
)

const (
	usernameMinLength        = 3
	usernameMaxLength        = 32
	backfillUsernameMaxLength = 64
)

// NormalizeEmail trims and lowercases an email address.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// NormalizeUsername trims, lowercases, strips leading/trailing dashes and
// underscores, and rejects characters outside [a-z0-9_-]. It enforces the
// public input length of 3–32, which does NOT apply to backfill generation.
// That path can use sanitiseUsernameToken or NormalizeBackfillUsername directly.
func NormalizeUsername(username string) (string, error) {
	s, err := sanitizeUsernameToken(username)
	if err != nil {
		return "", err
	}
	if len(s) < usernameMinLength {
		return "", ErrUsernameTooShort
	}
	if len(s) > usernameMaxLength {
		s = s[:usernameMaxLength]
	}
	return s, nil
}

// NormalizeBackfillUsername is like NormalizeUsername but accepts up to 64
// characters (the column width). It is intended for migration and store-level
// usage only — public inputs must go through NormalizeUsername.
func NormalizeBackfillUsername(username string) (string, error) {
	s, err := sanitizeUsernameToken(username)
	if err != nil {
		return "", err
	}
	if len(s) < usernameMinLength {
		return "", ErrUsernameTooShort
	}
	if len(s) > backfillUsernameMaxLength {
		s = s[:backfillUsernameMaxLength]
	}
	return s, nil
}

// NormalizeNickname trims the value. If the result is empty, fallback is
// returned unmodified.
func NormalizeNickname(nickname, fallback string) string {
	v := strings.TrimSpace(nickname)
	if v == "" {
		return fallback
	}
	return v
}

// UsernameFromEmail derives a sanitised username token from the email
// local-part. Characters outside [a-z0-9_-] are folded into a single dash.
// Leading/trailing dashes and underscores are removed. The result is empty
// when the sanitised length is < 3.
func UsernameFromEmail(email string) string {
	email = strings.TrimSpace(email)
	at := strings.Index(email, "@")
	if at <= 0 {
		return ""
	}
	local := strings.ToLower(email[:at])

	var b strings.Builder
	prevDash := false
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '_':
			b.WriteRune(r)
			prevDash = false
		case r == '-', r == '.', r == '+':
			if b.Len() > 0 && !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	candidate := strings.Trim(b.String(), "-_")
	if len(candidate) < usernameMinLength {
		return ""
	}
	if len(candidate) > backfillUsernameMaxLength {
		candidate = candidate[:backfillUsernameMaxLength]
	}
	return candidate
}

// IsUsernameLikeIdentifier reports whether identifier looks like a username
// (does not contain '@') rather than an email. Empty strings return false.
func IsUsernameLikeIdentifier(identifier string) bool {
	if identifier == "" {
		return false
	}
	return !strings.Contains(identifier, "@")
}

// ----- internal helpers -----

func sanitizeUsernameToken(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.ToLower(raw)
	for _, r := range raw {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '_' || r == '-' {
			continue
		}
		return "", fmt.Errorf("%w: %q", ErrUsernameInvalid, raw)
	}
	plain := strings.Trim(raw, "-_")
	if plain == "" {
		return "", fmt.Errorf("%w: empty after trimming", ErrUsernameInvalid)
	}
	return plain, nil
}

