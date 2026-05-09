package oidc

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/ratelimit"
)

const (
	authorizeRateLimitScope    = "oidc_authorize"
	authorizeRateLimitLimit    = 60
	authorizeRateLimitWindow   = time.Minute
	oidcRefreshRateLimitScope  = "oidc_refresh"
	oidcRefreshRateLimitLimit  = 20
	oidcRefreshRateLimitWindow = 10 * time.Minute
)

func (s *Service) SetRateLimiter(limiter *ratelimit.Service) {
	s.rateLimiter = limiter
}

func (h *Handler) allowAuthorizeRateLimit(c *gin.Context, clientID string) bool {
	if h.service.rateLimiter == nil {
		return true
	}

	result, err := h.service.rateLimiter.Allow(c.Request.Context(), authorizeRateLimitScope, oidcRateLimitKey(c, clientID), authorizeRateLimitLimit, authorizeRateLimitWindow)
	if err != nil {
		oauthError(c, http.StatusServiceUnavailable, "temporarily_unavailable")
		return false
	}
	if result.Allowed {
		return true
	}

	setOIDCRetryAfterHeader(c, result.RetryAfter)
	oauthError(c, http.StatusTooManyRequests, "rate_limited")
	return false
}

func (h *Handler) allowRefreshRateLimit(c *gin.Context, clientID string) bool {
	if h.service.rateLimiter == nil {
		return true
	}

	result, err := h.service.rateLimiter.Allow(c.Request.Context(), oidcRefreshRateLimitScope, oidcRateLimitKey(c, clientID), oidcRefreshRateLimitLimit, oidcRefreshRateLimitWindow)
	if err != nil {
		oauthError(c, http.StatusServiceUnavailable, "temporarily_unavailable")
		return false
	}
	if result.Allowed {
		return true
	}

	setOIDCRetryAfterHeader(c, result.RetryAfter)
	oauthError(c, http.StatusTooManyRequests, "rate_limited")
	return false
}

func oidcRateLimitKey(c *gin.Context, clientID string) string {
	ip := strings.TrimSpace(c.ClientIP())
	if ip == "" {
		ip = "unknown"
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return ip
	}
	return fmt.Sprintf("%s|%s", ip, clientID)
}

func setOIDCRetryAfterHeader(c *gin.Context, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
}
