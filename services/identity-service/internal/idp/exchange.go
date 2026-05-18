package idp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/session"
)

const exchangeCodeTTL = 60 * time.Second
const externalOAuthStateTTL = 10 * time.Minute

var ErrExchangeCodeInvalid = errors.New("exchange code invalid")

type ExchangeStore struct {
	client *redis.Client
}

type ExchangePayload struct {
	Provider string            `json:"provider"`
	Tokens   session.TokenPair `json:"tokens"`
	User     ExchangeUser      `json:"user"`
	ReturnTo string            `json:"return_to,omitempty"`
}

type ExchangeUser struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

type OAuthStatePayload struct {
	ReturnTo string `json:"return_to,omitempty"`
	Flow     string `json:"flow,omitempty"`
	UserID   int64  `json:"user_id,omitempty"`
}

func NewExchangeStore(client *redis.Client) *ExchangeStore {
	return &ExchangeStore{client: client}
}

func (s *ExchangeStore) Save(ctx context.Context, payload ExchangePayload) (string, error) {
	if s == nil || s.client == nil {
		return "", errors.New("exchange store redis client is nil")
	}
	code, err := randomExchangeCode()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if err := s.client.Set(ctx, cache.ExternalLoginExchangeKey(code), data, exchangeCodeTTL).Err(); err != nil {
		return "", err
	}
	return code, nil
}

func (s *ExchangeStore) Consume(ctx context.Context, code string) (*ExchangePayload, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("exchange store redis client is nil")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, ErrExchangeCodeInvalid
	}

	data, err := s.client.GetDel(ctx, cache.ExternalLoginExchangeKey(code)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrExchangeCodeInvalid
	}
	if err != nil {
		return nil, err
	}

	var payload ExchangePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *ExchangeStore) SaveOAuthState(ctx context.Context, state string, payload OAuthStatePayload) error {
	if s == nil || s.client == nil {
		return errors.New("exchange store redis client is nil")
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return ErrExchangeCodeInvalid
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, cache.ExternalOAuthStateKey(state), data, externalOAuthStateTTL).Err()
}

func (s *ExchangeStore) ConsumeOAuthState(ctx context.Context, state string) (*OAuthStatePayload, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("exchange store redis client is nil")
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, ErrExchangeCodeInvalid
	}
	data, err := s.client.GetDel(ctx, cache.ExternalOAuthStateKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return &OAuthStatePayload{}, nil
	}
	if err != nil {
		return nil, err
	}
	var payload OAuthStatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func randomExchangeCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
