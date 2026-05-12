package lockout

import (
	"context"
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

// IsLocked returns (locked, remainingSeconds, error).
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

// RecordFailure increments the failure counter. If the threshold is reached,
// it sets the lockout key. Returns (nowLocked, remainingLockSeconds, error).
func (m *Manager) RecordFailure(ctx context.Context, userID int64) (bool, int64, error) {
	if m == nil || m.redis == nil {
		return false, 0, nil
	}

	failKey := cache.LockoutFailuresKey(userID)
	pipe := m.redis.TxPipeline()
	incrCmd := pipe.Incr(ctx, failKey)
	ttlCmd := pipe.TTL(ctx, failKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}

	count := incrCmd.Val()
	// Set/refresh the failure window TTL on first increment or if key had no TTL.
	if count == 1 || ttlCmd.Val() <= 0 {
		_ = m.redis.Expire(ctx, failKey, m.failureWindow)
	}

	if count >= m.threshold {
		lockKey := cache.LockoutLockedKey(userID)
		if err := m.redis.Set(ctx, lockKey, "1", m.duration).Err(); err != nil {
			return true, int64(m.duration.Seconds()), err
		}
		return true, int64(m.duration.Seconds()), nil
	}
	return false, 0, nil
}

// Reset clears the failure counter after a successful login.
func (m *Manager) Reset(ctx context.Context, userID int64) error {
	if m == nil || m.redis == nil {
		return nil
	}
	return m.redis.Del(ctx, cache.LockoutFailuresKey(userID)).Err()
}

// Unlock manually removes the lockout (admin action).
func (m *Manager) Unlock(ctx context.Context, userID int64) error {
	if m == nil || m.redis == nil {
		return nil
	}
	return m.redis.Del(ctx,
		cache.LockoutLockedKey(userID),
		cache.LockoutFailuresKey(userID),
	).Err()
}
