// Package lockout implements temporary account lockout after consecutive
// authentication failures. State is stored in Redis with TTL-based auto-expiry.
package lockout

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
)

// Manager tracks consecutive login failures per account and enforces
// temporary soft-lockout using Redis TTL keys.
type Manager struct {
	redis     *redis.Client
	threshold int64
	duration  time.Duration
	// failureWindow is the sliding window for the failure counter.
	// Defaults to 30 minutes so that old failures don't count forever.
	failureWindow time.Duration
}

// recordFailureScript atomically: (1) short-circuits if already locked, (2)
// increments the windowed failure counter, (3) sets the lock with SETNX once
// the counter reaches threshold. Done in Lua so that concurrent failed logins
// cannot race past the threshold check.
var recordFailureScript = redis.NewScript(`
local failKey = KEYS[1]
local lockKey = KEYS[2]
local window = tonumber(ARGV[1])
local threshold = tonumber(ARGV[2])
local duration = tonumber(ARGV[3])

local lockTTL = redis.call('TTL', lockKey)
if lockTTL > 0 then
	return {1, lockTTL}
end

local count = redis.call('INCR', failKey)
redis.call('EXPIRE', failKey, window)

if count >= threshold then
	if redis.call('SETNX', lockKey, '1') == 1 then
		redis.call('EXPIRE', lockKey, duration)
		return {1, duration}
	end

	lockTTL = redis.call('TTL', lockKey)
	if lockTTL < 0 then
		lockTTL = duration
	end
	return {1, lockTTL}
end

return {0, 0}
`)

// NewManager creates a lockout Manager with sensible defaults.
//
// Call chain: auth handler → NewManager (wire) → (Redis client passed in at construction)
func NewManager(redisClient *redis.Client, threshold int64, duration time.Duration) *Manager {
	if threshold <= 0 {
		threshold = 5
	}
	if duration <= 0 {
		duration = 15 * time.Minute
	}
	return &Manager{
		redis:         redisClient,
		threshold:     threshold,
		duration:      duration,
		failureWindow: 30 * time.Minute,
	}
}

// IsLocked reports whether the account is currently locked, and if so returns the remaining TTL in seconds.
//
// Call chain: auth middleware → IsLocked → Redis TTL
func (m *Manager) IsLocked(ctx context.Context, userID int64) (bool, int64, error) {
	if m == nil || m.redis == nil {
		return false, 0, nil
	}
	ttl, err := m.redis.TTL(ctx, cache.LockoutLockedKey(userID)).Result()
	if err != nil {
		return false, 0, err
	}
	if ttl <= 0 {
		return false, 0, nil
	}
	return true, int64(ttl.Seconds()), nil
}

// RecordFailure atomically increments the sliding-window failure counter and
// sets the lockout key when the threshold is reached.
//
// Call chain: login handler → RecordFailure → recordFailureScript (Lua) → Redis INCR / SETNX
func (m *Manager) RecordFailure(ctx context.Context, userID int64) (bool, int64, error) {
	if m == nil || m.redis == nil {
		return false, 0, nil
	}

	result, err := recordFailureScript.Run(ctx, m.redis, []string{
		cache.LockoutFailuresKey(userID),
		cache.LockoutLockedKey(userID),
	}, int64(m.failureWindow/time.Second), m.threshold, int64(m.duration/time.Second)).Result()
	if err != nil {
		return false, 0, err
	}

	values, ok := result.([]interface{})
	if !ok || len(values) != 2 {
		return false, 0, fmt.Errorf("unexpected lockout script result: %#v", result)
	}
	locked, ok := values[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("unexpected lockout script locked result: %#v", values[0])
	}
	remaining, ok := values[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("unexpected lockout script ttl result: %#v", values[1])
	}
	return locked == 1, remaining, nil
}

// Reset clears the failure counter after a successful login.
//
// Call chain: login handler (success) → Reset → Redis DEL
func (m *Manager) Reset(ctx context.Context, userID int64) error {
	if m == nil || m.redis == nil {
		return nil
	}
	return m.redis.Del(ctx, cache.LockoutFailuresKey(userID)).Err()
}

// Unlock removes both the lockout and failure keys (admin override).
//
// Call chain: admin API → Unlock → Redis DEL (2 keys)
func (m *Manager) Unlock(ctx context.Context, userID int64) error {
	if m == nil || m.redis == nil {
		return nil
	}
	return m.redis.Del(ctx,
		cache.LockoutLockedKey(userID),
		cache.LockoutFailuresKey(userID),
	).Err()
}
