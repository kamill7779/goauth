package session

import (
	stdhttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/ratelimit"
)

const (
	refreshRateLimitScope  = "session_refresh"
	refreshRateLimitLimit  = 20
	refreshRateLimitWindow = 10 * time.Minute
)

func (h *Handler) SetRateLimiter(limiter *ratelimit.Service) {
	h.rateLimiter = limiter
}

func (h *Handler) allowRefreshRateLimit(c *gin.Context) bool {
	if h.rateLimiter == nil {
		return true
	}

	result, err := h.rateLimiter.Allow(c.Request.Context(), refreshRateLimitScope, refreshRateLimitKey(c), refreshRateLimitLimit, refreshRateLimitWindow)
	if err != nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "rate_limit_unavailable"})
		return false
	}
	if result.Allowed {
		return true
	}

	seconds := int(result.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
	c.JSON(stdhttp.StatusTooManyRequests, gin.H{"error": "rate_limited"})
	return false
}

func refreshRateLimitKey(c *gin.Context) string {
	ip := strings.TrimSpace(c.ClientIP())
	if ip == "" {
		ip = "unknown"
	}
	return ip
}
