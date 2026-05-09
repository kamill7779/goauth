package ratelimit

import (
	"context"
	"strings"
	"time"

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

func NewService(redisClient *redis.Client) *Service {
	return &Service{redis: redisClient}
}

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
