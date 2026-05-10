package provisioning

import (
	"context"
	"errors"
	"testing"

	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}
	return db
}

func TestDefaultMembershipPolicyAddsConfiguredActiveTenants(t *testing.T) {
	db := newTestDB(t)
	tenantA := createTenant(t, db, "Public App", "public-app", store.TenantStatusActive)
	tenantB := createTenant(t, db, "Community", "community", store.TenantStatusActive)
	user := createUser(t, db, "member@example.com")

	policy := NewDefaultMembershipPolicy([]string{" public-app ", "community", "public-app"})
	created, err := policy.Apply(context.Background(), db, user.ID)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("created member count = %d, want 2", len(created))
	}

	assertActiveMembership(t, db, tenantA.ID, user.ID)
	assertActiveMembership(t, db, tenantB.ID, user.ID)

	var count int64
	if err := db.Model(&store.TenantMember{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count tenant members: %v", err)
	}
	if count != 2 {
		t.Fatalf("tenant member count = %d, want 2", count)
	}
}

func TestDefaultMembershipPolicyFailsWhenTenantSlugIsMissing(t *testing.T) {
	db := newTestDB(t)
	user := createUser(t, db, "missing@example.com")

	policy := NewDefaultMembershipPolicy([]string{"missing"})
	_, err := policy.Apply(context.Background(), db, user.ID)
	if !errors.Is(err, ErrDefaultTenantNotFound) {
		t.Fatalf("Apply() error = %v, want %v", err, ErrDefaultTenantNotFound)
	}

	var count int64
	if err := db.Model(&store.TenantMember{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count tenant members: %v", err)
	}
	if count != 0 {
		t.Fatalf("tenant member count = %d, want 0", count)
	}
}

func TestDefaultMembershipPolicyDoesNotOverrideExplicitExistingMembership(t *testing.T) {
	db := newTestDB(t)
	tenantRecord := createTenant(t, db, "Public App", "public-app", store.TenantStatusActive)
	user := createUser(t, db, "disabled-member@example.com")
	member := store.TenantMember{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusDisabled,
	}
	if err := db.Create(&member).Error; err != nil {
		t.Fatalf("create disabled member: %v", err)
	}

	policy := NewDefaultMembershipPolicy([]string{"public-app"})
	created, err := policy.Apply(context.Background(), db, user.ID)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(created) != 0 {
		t.Fatalf("created member count = %d, want 0 for existing member", len(created))
	}

	var stored store.TenantMember
	if err := db.First(&stored, member.ID).Error; err != nil {
		t.Fatalf("load tenant member: %v", err)
	}
	if stored.Status != store.MemberStatusDisabled {
		t.Fatalf("member status = %q, want disabled", stored.Status)
	}
}

func createTenant(t *testing.T, db *gorm.DB, name, slug, status string) *store.Tenant {
	t.Helper()

	record := &store.Tenant{
		Name:   name,
		Slug:   slug,
		Status: status,
	}
	if err := db.Create(record).Error; err != nil {
		t.Fatalf("create tenant %q: %v", slug, err)
	}
	return record
}

func createUser(t *testing.T, db *gorm.DB, email string) *store.User {
	t.Helper()

	user := &store.User{
		Email:        email,
		DisplayName:  email,
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user %q: %v", email, err)
	}
	return user
}

func assertActiveMembership(t *testing.T, db *gorm.DB, tenantID, userID int64) {
	t.Helper()

	var count int64
	if err := db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ? AND status = ?", tenantID, userID, store.MemberStatusActive).
		Count(&count).Error; err != nil {
		t.Fatalf("count active membership: %v", err)
	}
	if count != 1 {
		t.Fatalf("active membership count = %d, want 1", count)
	}
}
