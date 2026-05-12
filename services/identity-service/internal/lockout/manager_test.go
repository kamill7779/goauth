package lockout_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/lockout"
)

func newTestManager(t *testing.T, threshold int64, duration time.Duration) (*lockout.Manager, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return lockout.NewManager(client, threshold, duration), mr
}

func TestIsLocked_NotLockedInitially(t *testing.T) {
	m, _ := newTestManager(t, 5, 15*time.Minute)
	locked, _, err := m.IsLocked(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("expected not locked initially")
	}
}

func TestRecordFailure_LocksAfterThreshold(t *testing.T) {
	m, _ := newTestManager(t, 3, 15*time.Minute)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		locked, _, err := m.RecordFailure(ctx, 42)
		if err != nil {
			t.Fatal(err)
		}
		if locked {
			t.Errorf("should not be locked after %d failures", i+1)
		}
	}

	locked, remaining, err := m.RecordFailure(ctx, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("expected locked after threshold")
	}
	if remaining <= 0 {
		t.Error("expected positive remaining seconds")
	}
}

func TestIsLocked_TrueAfterThreshold(t *testing.T) {
	m, _ := newTestManager(t, 2, 15*time.Minute)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, _, _ = m.RecordFailure(ctx, 7)
	}

	locked, _, err := m.IsLocked(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("expected locked")
	}
}

func TestRecordFailure_ExtendsSlidingWindowTTL(t *testing.T) {
	m, mr := newTestManager(t, 5, 15*time.Minute)
	ctx := context.Background()
	userID := int64(77)

	if _, _, err := m.RecordFailure(ctx, userID); err != nil {
		t.Fatalf("first failure: %v", err)
	}
	mr.FastForward(20 * time.Minute)

	if _, _, err := m.RecordFailure(ctx, userID); err != nil {
		t.Fatalf("second failure: %v", err)
	}

	ttl := mr.TTL(cache.LockoutFailuresKey(userID))
	if ttl < 25*time.Minute {
		t.Fatalf("failure TTL = %v, want sliding window near %v", ttl, 30*time.Minute)
	}
}

func TestRecordFailure_DoesNotExtendActiveLockTTL(t *testing.T) {
	m, mr := newTestManager(t, 2, 15*time.Minute)
	ctx := context.Background()
	userID := int64(88)

	for i := 0; i < 2; i++ {
		if _, _, err := m.RecordFailure(ctx, userID); err != nil {
			t.Fatalf("lock account: %v", err)
		}
	}

	mr.FastForward(5 * time.Minute)
	before := mr.TTL(cache.LockoutLockedKey(userID))

	if _, _, err := m.RecordFailure(ctx, userID); err != nil {
		t.Fatalf("record failure while locked: %v", err)
	}

	after := mr.TTL(cache.LockoutLockedKey(userID))
	if after > before {
		t.Fatalf("lock TTL extended from %v to %v", before, after)
	}
}

func TestReset_ClearsCounter(t *testing.T) {
	m, _ := newTestManager(t, 5, 15*time.Minute)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, _, _ = m.RecordFailure(ctx, 99)
	}
	if err := m.Reset(ctx, 99); err != nil {
		t.Fatal(err)
	}

	// After reset, 5 more failures should be needed to lock again.
	for i := 0; i < 4; i++ {
		locked, _, _ := m.RecordFailure(ctx, 99)
		if locked {
			t.Errorf("should not be locked after reset + %d failures", i+1)
		}
	}
}

func TestUnlock_ClearsLockout(t *testing.T) {
	m, _ := newTestManager(t, 2, 15*time.Minute)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		_, _, _ = m.RecordFailure(ctx, 55)
	}

	locked, _, _ := m.IsLocked(ctx, 55)
	if !locked {
		t.Fatal("expected locked before unlock")
	}

	if err := m.Unlock(ctx, 55); err != nil {
		t.Fatal(err)
	}

	locked, _, err := m.IsLocked(ctx, 55)
	if err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("expected unlocked after Unlock()")
	}
}

func TestNilManager_IsNoOp(t *testing.T) {
	var m *lockout.Manager
	ctx := context.Background()
	locked, _, err := m.IsLocked(ctx, 1)
	if err != nil || locked {
		t.Error("nil manager should be noop")
	}
	locked, _, err = m.RecordFailure(ctx, 1)
	if err != nil || locked {
		t.Error("nil manager RecordFailure should be noop")
	}
	if err := m.Reset(ctx, 1); err != nil {
		t.Error("nil manager Reset should be noop")
	}
}
