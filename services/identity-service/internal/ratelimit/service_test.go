package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
)

func TestAllowEnforcesLimitWithinWindow(t *testing.T) {
	mini := miniredis.RunT(t)
	client, err := cache.OpenRedis(config.Config{RedisURL: "redis://" + mini.Addr() + "/0"})
	if err != nil {
		t.Fatalf("cache.OpenRedis() error = %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})

	service := NewService(client)
	ctx := context.Background()

	first, err := service.Allow(ctx, "auth_login", "127.0.0.1|user@example.com", 2, time.Minute)
	if err != nil {
		t.Fatalf("Allow(first) error = %v", err)
	}
	if !first.Allowed || first.Count != 1 {
		t.Fatalf("first result = %#v, want allowed count=1", first)
	}

	second, err := service.Allow(ctx, "auth_login", "127.0.0.1|user@example.com", 2, time.Minute)
	if err != nil {
		t.Fatalf("Allow(second) error = %v", err)
	}
	if !second.Allowed || second.Count != 2 {
		t.Fatalf("second result = %#v, want allowed count=2", second)
	}

	third, err := service.Allow(ctx, "auth_login", "127.0.0.1|user@example.com", 2, time.Minute)
	if err != nil {
		t.Fatalf("Allow(third) error = %v", err)
	}
	if third.Allowed {
		t.Fatalf("third result = %#v, want denied", third)
	}
	if third.RetryAfter <= 0 {
		t.Fatalf("third retry_after = %v, want positive", third.RetryAfter)
	}
}

func TestAllowWithoutRedisFailsOpen(t *testing.T) {
	result, err := NewService(nil).Allow(context.Background(), "auth_login", "127.0.0.1", 1, time.Minute)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if !result.Allowed {
		t.Fatalf("result = %#v, want allowed", result)
	}
}
