package session

import (
	stdhttp "net/http"
	"strconv"
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

func (h *Handler) SetRateLimiter(limiter *ratelimit.Service) {
	h.rateLimiter = limiter
}

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

	seconds := int(result.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
	httpserver.Error(c, stdhttp.StatusTooManyRequests, "rate_limited")
	return false
}

func refreshRateLimitKey(c *gin.Context) string {
	ip := strings.TrimSpace(c.ClientIP())
	if ip == "" {
		ip = "unknown"
	}
	return ip
}
