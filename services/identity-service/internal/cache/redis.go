package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/config"
)

func OpenRedis(cfg config.Config) (*redis.Client, error) {
	redisURL := cfg.RedisURL
	if redisURL == "" {
		redisURL = "redis://127.0.0.1:6379/0"
	}

	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := redis.NewClient(options)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}
