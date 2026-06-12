package auth

import (
	"fmt"
	"time"
)

// LockoutError signals a temporary account lockout and carries the
// remaining duration so handlers can write a Retry-After header.
type LockoutError struct {
	RetryAfter time.Duration
}

func (e *LockoutError) Error() string {
	return fmt.Sprintf("account locked, retry after %s", e.RetryAfter)
}

// RateLimitError signals that a rate limit was exceeded.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited, retry after %s", e.RetryAfter)
}
