// Package ratelimit implements a sliding-window rate limiter backed by Redis
// INCR + EXPIRE. Each (scope, key) pair gets an independent counter.
package ratelimit

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
)

type Result struct {
	Allowed    bool
	Count      int64
	RetryAfter time.Duration
}

type Service struct {
	redis *redis.Client
}

// NewService creates a rate-limit Service backed by the given Redis client.
func NewService(redisClient *redis.Client) *Service {
	return &Service{redis: redisClient}
}

// Allow checks whether the (scope, key) pair is within its rate limit.
// Uses Redis INCR + EXPIRE: the first request in a window sets the TTL,
// subsequent requests increment the counter until it exceeds limit.
// A nil service or empty scope/key is a no-op (always allowed).
//
// Call chain: auth/oidc handler → ratelimit.Service.Allow → cache.RateLimitKey / Redis TxPipeline
func (s *Service) Allow(ctx context.Context, scope, key string, limit int64, window time.Duration) (Result, error) {
	if s == nil || s.redis == nil || limit <= 0 || window <= 0 {
		return Result{Allowed: true}, nil
	}

	scope = strings.TrimSpace(scope)
	key = strings.TrimSpace(key)
	if scope == "" || key == "" {
		return Result{Allowed: true}, nil
	}

	redisKey := cache.RateLimitKey(scope, key)
	pipe := s.redis.TxPipeline()
	countCmd := pipe.Incr(ctx, redisKey)
	ttlCmd := pipe.TTL(ctx, redisKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return Result{}, err
	}

	count := countCmd.Val()
	retryAfter := ttlCmd.Val()
	if count == 1 || retryAfter <= 0 {
		if err := s.redis.Expire(ctx, redisKey, window).Err(); err != nil {
			return Result{}, err
		}
		retryAfter = window
	}

	return Result{
		Allowed:    count <= limit,
		Count:      count,
		RetryAfter: retryAfter,
	}, nil
}

// SetRetryAfterHeader writes a standard Retry-After header (integer seconds,
// minimum 1) to the HTTP response.
//
// Call chain: any rate-limited handler → ratelimit.SetRetryAfterHeader → gin.Context.Header
func SetRetryAfterHeader(c *gin.Context, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
}
