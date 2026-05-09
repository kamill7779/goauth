package cache

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"goauth/services/identity-service/internal/config"
)

func TestOpenRedisBuildsClientFromConfiguredURL(t *testing.T) {
	mini := miniredis.RunT(t)

	cfg := config.Config{
		RedisURL: "redis://" + mini.Addr() + "/0",
	}

	client, err := OpenRedis(cfg)
	if err != nil {
		t.Fatalf("OpenRedis() error = %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Fatalf("client.Close() error = %v", err)
		}
	}()

	if pong, err := client.Ping(context.Background()).Result(); err != nil {
		t.Fatalf("Ping() error = %v", err)
	} else if pong != "PONG" {
		t.Fatalf("Ping() = %q, want PONG", pong)
	}
}
