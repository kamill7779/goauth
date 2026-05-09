package user

import (
	"context"
	"testing"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/store"
)

func newTestService(t *testing.T) *Service {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	return NewService(db, audit.NewService(db))
}

func TestListUsersReturnsUsers(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	if _, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "a@example.com",
		DisplayName: "A",
		Password:    "password-1",
	}); err != nil {
		t.Fatalf("CreateUser(a) error = %v", err)
	}
	if _, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "b@example.com",
		DisplayName: "B",
		Password:    "password-2",
	}); err != nil {
		t.Fatalf("CreateUser(b) error = %v", err)
	}

	users, err := service.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("user count = %d, want 2", len(users))
	}
}

func TestDisableAndEnableUser(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "toggle@example.com",
		DisplayName: "Toggle",
		Password:    "password-1",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if err := service.DisableUser(ctx, record.ID); err != nil {
		t.Fatalf("DisableUser() error = %v", err)
	}
	disabled, err := service.GetUser(ctx, record.ID)
	if err != nil {
		t.Fatalf("GetUser(disabled) error = %v", err)
	}
	if disabled.Status != store.UserStatusDisabled {
		t.Fatalf("status after disable = %q, want %q", disabled.Status, store.UserStatusDisabled)
	}

	if err := service.EnableUser(ctx, record.ID); err != nil {
		t.Fatalf("EnableUser() error = %v", err)
	}
	enabled, err := service.GetUser(ctx, record.ID)
	if err != nil {
		t.Fatalf("GetUser(enabled) error = %v", err)
	}
	if enabled.Status != store.UserStatusActive {
		t.Fatalf("status after enable = %q, want %q", enabled.Status, store.UserStatusActive)
	}
}

func TestResetPasswordUpdatesStoredHash(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "reset@example.com",
		DisplayName: "Reset",
		Password:    "old-password",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	oldHash := record.PasswordHash

	if err := service.ResetPassword(ctx, record.ID, "new-password"); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	updated, err := service.GetUser(ctx, record.ID)
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if updated.PasswordHash == oldHash {
		t.Fatal("expected password hash to change")
	}

	var count int64
	if err := service.db.Model(&store.AuditLog{}).Where("action = ?", audit.ActionPasswordReset).Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("password reset audit log count = %d, want 1", count)
	}
}

func TestDisableProtectedUserFails(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	protected, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "root@example.com",
		DisplayName: "Root",
		Password:    "password-1",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := service.MarkSystemUser(ctx, protected.ID, "root"); err != nil {
		t.Fatalf("MarkSystemUser() error = %v", err)
	}

	err = service.DisableUser(ctx, protected.ID)
	if err == nil {
		t.Fatal("expected protected user disable to fail")
	}
	if err != ErrProtectedUser {
		t.Fatalf("DisableUser() error = %v, want %v", err, ErrProtectedUser)
	}
}

func TestDisableSystemRoleUserFails(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	protected, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "admin@example.com",
		DisplayName: "Admin",
		Password:    "password-1",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := service.MarkSystemUser(ctx, protected.ID, "system-admin"); err != nil {
		t.Fatalf("MarkSystemUser() error = %v", err)
	}

	err = service.DisableUser(ctx, protected.ID)
	if err == nil {
		t.Fatal("expected system-role user disable to fail")
	}
	if err != ErrProtectedUser {
		t.Fatalf("DisableUser() error = %v, want %v", err, ErrProtectedUser)
	}
}
