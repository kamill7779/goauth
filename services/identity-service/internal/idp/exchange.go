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

// NewExchangeStore creates an ExchangeStore backed by Redis.
func NewExchangeStore(client *redis.Client) *ExchangeStore {
	return &ExchangeStore{client: client}
}

// Save stores an ExchangePayload under a random single-use exchange code in
// Redis with a 60-second TTL. Returns the one-time code.
//
// Call chain: handler.callback → Save → Redis SET
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

// Consume atomically reads and deletes the exchange payload identified by
// code. Returns ErrExchangeCodeInvalid when the code is missing or expired.
//
// Call chain: handler.exchange → Consume → Redis GETDEL
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

// SaveOAuthState persists the OAuth state payload in Redis with a 10-minute
// TTL so the callback can recover flow parameters.
//
// Call chain: handler.start / startAccountBind → SaveOAuthState → Redis SET
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

// ConsumeOAuthState atomically reads and deletes the OAuth state payload.
// Returns an empty payload when the state is not found (not an error).
//
// Call chain: handler.callback → ConsumeOAuthState → Redis GETDEL
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

// randomExchangeCode generates a base64url-encoded 256-bit random value for
// use as a one-time exchange code.
//
// Call chain: Save → randomExchangeCode
func randomExchangeCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
