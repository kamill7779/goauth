package auth

import (
	"fmt"
	stdhttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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

func (h *Handler) SetRateLimiter(limiter *ratelimit.Service) {
	h.rateLimiter = limiter
}

func (h *Handler) allowJSONRateLimit(c *gin.Context, scope, key string, limit int64, window time.Duration) bool {
	if h.rateLimiter == nil {
		return true
	}

	result, err := h.rateLimiter.Allow(c.Request.Context(), scope, key, limit, window)
	if err != nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "rate_limit_unavailable"})
		return false
	}
	if result.Allowed {
		return true
	}

	setRetryAfterHeader(c, result.RetryAfter)
	c.JSON(stdhttp.StatusTooManyRequests, gin.H{"error": "rate_limited"})
	return false
}

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

func setRetryAfterHeader(c *gin.Context, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
}

func rateLimitEmailCodeKey(c *gin.Context, purpose, email string) string {
	return fmt.Sprintf("%s|%s", strings.TrimSpace(strings.ToLower(purpose)), rateLimitKey(c, email))
}
