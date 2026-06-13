package auth

import (
	"fmt"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/ratelimit"
)

const (
	emailCodeRateLimitScope      = "auth_email_code"
	emailCodeRateLimitLimit      = 5
	emailCodeRateLimitWindow     = 10 * time.Minute
	loginRateLimitScope          = "auth_login"
	loginRateLimitLimit          = 10
	loginRateLimitWindow         = 10 * time.Minute
	passwordResetRateLimitScope  = "auth_password_reset"
	passwordResetRateLimitLimit  = 5
	passwordResetRateLimitWindow = 10 * time.Minute
)

// SetRateLimiter injects a rate-limit service for the auth handler.
func (h *Handler) SetRateLimiter(limiter *ratelimit.Service) {
	h.rateLimiter = limiter
}

// allowJSONRateLimit checks the rate limit and writes a JSON error response if
// exceeded. Returns true when the request may proceed.
//
// Call chain: handler methods → allowJSONRateLimit → rateLimiter.Allow
func (h *Handler) allowJSONRateLimit(c *gin.Context, scope, key string, limit int64, window time.Duration) bool {
	if h.rateLimiter == nil {
		return true
	}

	result, err := h.rateLimiter.Allow(c.Request.Context(), scope, key, limit, window)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "rate_limit_unavailable")
		return false
	}
	if result.Allowed {
		return true
	}

	ratelimit.SetRetryAfterHeader(c, result.RetryAfter)
	httpserver.Error(c, stdhttp.StatusTooManyRequests, "rate_limited")
	return false
}

// rateLimitKey builds a composite key from the client IP and optional identity parts.
func rateLimitKey(c *gin.Context, identityParts ...string) string {
	parts := make([]string, 0, len(identityParts)+1)
	ip := strings.TrimSpace(c.ClientIP())
	if ip == "" {
		ip = "unknown"
	}
	parts = append(parts, ip)
	for _, part := range identityParts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "|")
}


// rateLimitEmailCodeKey builds a rate-limit key that includes the purpose and email.
func rateLimitEmailCodeKey(c *gin.Context, purpose, email string) string {
	return fmt.Sprintf("%s|%s", strings.TrimSpace(strings.ToLower(purpose)), rateLimitKey(c, email))
}
