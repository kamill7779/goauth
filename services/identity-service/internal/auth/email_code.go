package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
)

const (
	EmailCodePurposeRegister      = "register"
	EmailCodePurposePasswordReset = "password_reset"
	emailCodeTTL                  = 10 * time.Minute
)

func generateEmailCode() (string, error) {
	limit := big.NewInt(1000000)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", value.Int64()), nil
}

func normalizeEmailCodePurpose(purpose string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(purpose)) {
	case "", EmailCodePurposeRegister:
		return EmailCodePurposeRegister, nil
	case EmailCodePurposePasswordReset:
		return EmailCodePurposePasswordReset, nil
	default:
		return "", errors.New("unsupported email code purpose")
	}
}

func storeEmailCode(ctx context.Context, client *redis.Client, purpose, email, code string) error {
	return client.Set(ctx, cache.EmailCodeKey(purpose, email), code, emailCodeTTL).Err()
}

func loadEmailCode(ctx context.Context, client *redis.Client, purpose, email string) (string, error) {
	return client.Get(ctx, cache.EmailCodeKey(purpose, email)).Result()
}
