package session

import (
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/ratelimit"
)

const (
	refreshRateLimitScope  = "session_refresh"
	refreshRateLimitLimit  = 20
	refreshRateLimitWindow = 10 * time.Minute
)

// Deprecated: use constructor injection.
func (h *Handler) SetRateLimiter(limiter *ratelimit.Service) {
	h.rateLimiter = limiter
}

// allowRefreshRateLimit checks the refresh rate limit and writes a JSON error
// response if exceeded. Returns true when the request may proceed.
//
// Call chain: handler.refresh → allowRefreshRateLimit → rateLimiter.Allow
func (h *Handler) allowRefreshRateLimit(c *gin.Context) bool {
	if h.rateLimiter == nil {
		return true
	}

	result, err := h.rateLimiter.Allow(c.Request.Context(), refreshRateLimitScope, refreshRateLimitKey(c), refreshRateLimitLimit, refreshRateLimitWindow)
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

// refreshRateLimitKey builds a rate-limit key from the client IP.
func refreshRateLimitKey(c *gin.Context) string {
	ip := strings.TrimSpace(c.ClientIP())
	if ip == "" {
		ip = "unknown"
	}
	return ip
}
