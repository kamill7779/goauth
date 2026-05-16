package idp

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/session"
)

func TestExchangeStoreConsumesCodeOnce(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store := NewExchangeStore(client)

	code, err := store.Save(context.Background(), ExchangePayload{
		Provider: "github",
		Tokens: session.TokenPair{
			AccessToken:  "access",
			RefreshToken: "refresh",
			SessionID:    "sid",
		},
		User: ExchangeUser{
			ID:    12,
			Email: "member@example.com",
		},
		ReturnTo: "/admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("expected exchange code")
	}

	payload, err := store.Consume(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Provider != "github" {
		t.Fatalf("provider = %q, want github", payload.Provider)
	}
	if payload.Tokens.AccessToken != "access" || payload.Tokens.RefreshToken != "refresh" {
		t.Fatalf("tokens = %+v, want saved pair", payload.Tokens)
	}
	if payload.User.Email != "member@example.com" {
		t.Fatalf("user email = %q, want member@example.com", payload.User.Email)
	}
	if payload.ReturnTo != "/admin" {
		t.Fatalf("return_to = %q, want /admin", payload.ReturnTo)
	}
	if _, err := store.Consume(context.Background(), code); !errors.Is(err, ErrExchangeCodeInvalid) {
		t.Fatalf("second consume err = %v, want ErrExchangeCodeInvalid", err)
	}
}
