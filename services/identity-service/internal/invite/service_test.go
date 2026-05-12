package invite_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goauth/services/identity-service/internal/invite"
	"goauth/services/identity-service/internal/mailer"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

var inviteTokenRegexp = regexp.MustCompile(`token=([A-Za-z0-9._-]+)`)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "invite-test.db")
	db, err := gorm.Open(sqlite.Open(dbPath+"?_pragma=busy_timeout(5000)"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&store.User{}, &store.Invite{}, &store.TenantMember{}, &store.MemberRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(10)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}
	})
	return db
}

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

type captureSender struct {
	mu       sync.Mutex
	messages []mailer.Message
}

func (s *captureSender) Send(_ context.Context, message mailer.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, message)
	return nil
}

func (s *captureSender) lastToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		t.Fatal("expected at least one sent invite message")
	}
	body := s.messages[len(s.messages)-1].Body
	match := inviteTokenRegexp.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("could not extract invite token from message body: %q", body)
	}
	return match[1]
}

func mustCreateUser(t *testing.T, db *gorm.DB, email string) *store.User {
	t.Helper()
	now := time.Now()
	user := &store.User{
		Email:           email,
		Username:        email[:len(email)-len("@example.com")],
		Nickname:        email,
		PasswordHash:    "hash",
		DisplayName:     email,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func TestCreate_StoresInvite(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	svc := invite.NewService(db, key, nil, nil, "GoAuth", "https://app.example.com")

	inv, err := svc.Create(context.Background(), invite.CreateInput{
		TenantID:    1,
		RoleID:      2,
		TargetEmail: "user@example.com",
		InviterID:   99,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv.ID == 0 {
		t.Error("expected non-zero invite ID")
	}
	if inv.Status != store.InviteStatusPending {
		t.Errorf("expected pending status, got %q", inv.Status)
	}
}

func TestRedeem_AddsUserToTenant(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	sender := &captureSender{}
	svc := invite.NewService(db, key, sender, nil, "GoAuth", "https://app.example.com")
	user := mustCreateUser(t, db, "alice@example.com")

	if _, err := svc.Create(context.Background(), invite.CreateInput{
		TenantID:    10,
		RoleID:      5,
		TargetEmail: user.Email,
		InviterID:   1,
	}); err != nil {
		t.Fatalf("create invite: %v", err)
	}

	if err := svc.Redeem(context.Background(), invite.RedeemInput{
		Token:  sender.lastToken(t),
		UserID: user.ID,
	}); err != nil {
		t.Fatalf("redeem invite: %v", err)
	}

	var members []store.TenantMember
	if err := db.Where("tenant_id = ? AND user_id = ? AND deleted_at IS NULL", 10, user.ID).Find(&members).Error; err != nil {
		t.Fatalf("load tenant members: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("tenant membership count = %d, want 1", len(members))
	}

	var memberRole store.MemberRole
	if err := db.Where("member_id = ? AND role_id = ?", members[0].ID, 5).First(&memberRole).Error; err != nil {
		t.Fatalf("expected role assignment: %v", err)
	}

	var storedInvite store.Invite
	if err := db.First(&storedInvite).Error; err != nil {
		t.Fatalf("load invite: %v", err)
	}
	if storedInvite.Status != store.InviteStatusRedeemed {
		t.Fatalf("invite status = %q, want %q", storedInvite.Status, store.InviteStatusRedeemed)
	}
}

func TestRedeem_RejectsInviteForDifferentUserEmail(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	sender := &captureSender{}
	svc := invite.NewService(db, key, sender, nil, "GoAuth", "https://app.example.com")
	owner := mustCreateUser(t, db, "alice@example.com")
	other := mustCreateUser(t, db, "mallory@example.com")

	if _, err := svc.Create(context.Background(), invite.CreateInput{
		TenantID:    1,
		RoleID:      7,
		TargetEmail: owner.Email,
		InviterID:   1,
	}); err != nil {
		t.Fatalf("create invite: %v", err)
	}

	err := svc.Redeem(context.Background(), invite.RedeemInput{
		Token:  sender.lastToken(t),
		UserID: other.ID,
	})
	if err == nil {
		t.Fatal("expected redeem to reject a different logged-in user")
	}

	var count int64
	if err := db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ? AND deleted_at IS NULL", 1, other.ID).
		Count(&count).Error; err != nil {
		t.Fatalf("count tenant members: %v", err)
	}
	if count != 0 {
		t.Fatalf("membership count = %d, want 0", count)
	}
}

func TestRedeem_OnlySucceedsOnce(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	sender := &captureSender{}
	svc := invite.NewService(db, key, sender, nil, "GoAuth", "https://app.example.com")
	user := mustCreateUser(t, db, "alice@example.com")

	member := &store.TenantMember{
		TenantID:  11,
		UserID:    user.ID,
		Status:    store.MemberStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Create(member).Error; err != nil {
		t.Fatalf("create existing member: %v", err)
	}
	if err := db.Create(&store.MemberRole{MemberID: member.ID, RoleID: 3}).Error; err != nil {
		t.Fatalf("create existing member role: %v", err)
	}

	if _, err := svc.Create(context.Background(), invite.CreateInput{
		TenantID:    11,
		RoleID:      3,
		TargetEmail: user.Email,
		InviterID:   1,
	}); err != nil {
		t.Fatalf("create invite: %v", err)
	}

	token := sender.lastToken(t)
	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			errs <- svc.Redeem(context.Background(), invite.RedeemInput{
				Token:  token,
				UserID: user.ID,
			})
		}()
	}
	close(start)

	var successCount int
	var redeemedCount int
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, invite.ErrInviteRedeemed):
			redeemedCount++
		default:
			t.Fatalf("unexpected redeem error: %v", err)
		}
	}
	if successCount != 1 || redeemedCount != 1 {
		t.Fatalf("successes=%d redeemed_errors=%d, want 1 and 1", successCount, redeemedCount)
	}
}

func TestRedeem_RestoresSoftDeletedTenantMember(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	sender := &captureSender{}
	svc := invite.NewService(db, key, sender, nil, "GoAuth", "https://app.example.com")
	user := mustCreateUser(t, db, "restored@example.com")

	member := &store.TenantMember{
		TenantID:  21,
		UserID:    user.ID,
		Status:    store.MemberStatusDisabled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Create(member).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	if err := db.Delete(member).Error; err != nil {
		t.Fatalf("soft delete member: %v", err)
	}

	if _, err := svc.Create(context.Background(), invite.CreateInput{
		TenantID:    21,
		RoleID:      9,
		TargetEmail: user.Email,
		InviterID:   1,
	}); err != nil {
		t.Fatalf("create invite: %v", err)
	}

	if err := svc.Redeem(context.Background(), invite.RedeemInput{
		Token:  sender.lastToken(t),
		UserID: user.ID,
	}); err != nil {
		t.Fatalf("redeem invite: %v", err)
	}

	var restored store.TenantMember
	if err := db.Unscoped().
		Where("tenant_id = ? AND user_id = ?", 21, user.ID).
		First(&restored).Error; err != nil {
		t.Fatalf("load restored member: %v", err)
	}
	if restored.ID != member.ID {
		t.Fatalf("restored member id = %d, want %d", restored.ID, member.ID)
	}
	if restored.DeletedAt.Valid {
		t.Fatal("restored member is still soft deleted")
	}
	if restored.Status != store.MemberStatusActive {
		t.Fatalf("restored member status = %q, want %q", restored.Status, store.MemberStatusActive)
	}
}

func TestRedeem_RejectsExpiredInvite(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	svc := invite.NewService(db, key, nil, nil, "GoAuth", "https://app.example.com")

	expiredInvite := &store.Invite{
		TokenHash:     "expiredhash",
		TenantID:      1,
		RoleID:        1,
		InviterUserID: 1,
		TargetEmail:   "expired@example.com",
		Status:        store.InviteStatusPending,
		ExpiresAt:     time.Now().Add(-1 * time.Hour),
		CreatedAt:     time.Now().Add(-2 * time.Hour),
	}
	if err := db.Create(expiredInvite).Error; err != nil {
		t.Fatalf("store expired invite: %v", err)
	}

	err := svc.Redeem(context.Background(), invite.RedeemInput{
		Token:  "bad",
		UserID: 1,
	})
	if err == nil {
		t.Error("expected error")
	}
}

func TestRevoke_MarksInviteRevoked(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	svc := invite.NewService(db, key, nil, nil, "GoAuth", "https://app.example.com")

	inv, _ := svc.Create(context.Background(), invite.CreateInput{
		TenantID:    1,
		RoleID:      1,
		TargetEmail: "revoke@example.com",
		InviterID:   1,
	})

	if err := svc.Revoke(context.Background(), inv.ID); err != nil {
		t.Fatalf("revoke error: %v", err)
	}

	var updated store.Invite
	db.First(&updated, inv.ID)
	if updated.Status != store.InviteStatusRevoked {
		t.Errorf("expected revoked status, got %q", updated.Status)
	}
}

func TestRevoke_NonexistentInvite(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	svc := invite.NewService(db, key, nil, nil, "GoAuth", "https://app.example.com")

	err := svc.Revoke(context.Background(), 99999)
	if err == nil {
		t.Error("expected error for nonexistent invite")
	}
}

func TestList_ReturnsPaginatedInvites(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)
	svc := invite.NewService(db, key, nil, nil, "GoAuth", "https://app.example.com")

	for i := 0; i < 5; i++ {
		_, _ = svc.Create(context.Background(), invite.CreateInput{
			TenantID:    20,
			RoleID:      1,
			TargetEmail: "user@example.com",
			InviterID:   1,
		})
	}

	invites, total, err := svc.List(context.Background(), 20, 1, 3)
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	if len(invites) != 3 {
		t.Errorf("expected 3 invites on page 1, got %d", len(invites))
	}
}
