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

func TestRootEmailWithoutSystemRoleCanBeDisabled(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "root@example.com",
		DisplayName: "Root",
		Password:    "password-1",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if err := service.DisableUser(ctx, record.ID); err != nil {
		t.Fatalf("DisableUser() error = %v", err)
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

func TestInactiveSystemRoleMembershipDoesNotProtectUser(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "inactive-admin@example.com",
		DisplayName: "Inactive Admin",
		Password:    "password-1",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := service.MarkSystemUser(ctx, record.ID, "system-admin"); err != nil {
		t.Fatalf("MarkSystemUser() error = %v", err)
	}
	if err := service.db.Model(&store.TenantMember{}).
		Where("user_id = ?", record.ID).
		Update("status", store.MemberStatusDisabled).Error; err != nil {
		t.Fatalf("disable tenant member: %v", err)
	}

	if err := service.DisableUser(ctx, record.ID); err != nil {
		t.Fatalf("DisableUser() error = %v", err)
	}
}

func TestCrossTenantSystemRoleBindingDoesNotProtectUser(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "cross-tenant-admin@example.com",
		DisplayName: "Cross Tenant Admin",
		Password:    "password-1",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	tenantA := store.Tenant{Name: "Tenant A", Slug: "tenant-a", Status: store.TenantStatusActive}
	tenantB := store.Tenant{Name: "Tenant B", Slug: "tenant-b", Status: store.TenantStatusActive}
	if err := service.db.Create(&tenantA).Error; err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	if err := service.db.Create(&tenantB).Error; err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	member := store.TenantMember{TenantID: tenantA.ID, UserID: record.ID, Status: store.MemberStatusActive}
	if err := service.db.Create(&member).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	role := store.Role{TenantID: tenantB.ID, Name: "System Admin", Code: "system-admin", IsSystem: true}
	if err := service.db.Create(&role).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := service.db.Create(&store.MemberRole{MemberID: member.ID, RoleID: role.ID}).Error; err != nil {
		t.Fatalf("create cross-tenant member role: %v", err)
	}

	if err := service.DisableUser(ctx, record.ID); err != nil {
		t.Fatalf("DisableUser() error = %v", err)
	}
}

func TestEnsureBootstrapAdminCreatesAndMarksSystemUser(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.EnsureBootstrapAdmin(ctx, BootstrapAdminInput{
		Email:       "bootstrap@example.com",
		DisplayName: "Bootstrap Admin",
		Password:    "ChangeMe123!",
		RoleCode:    "root",
	})
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin() error = %v", err)
	}
	if record.Status != store.UserStatusActive {
		t.Fatalf("status = %q, want %q", record.Status, store.UserStatusActive)
	}
	if record.EmailVerifiedAt == nil {
		t.Fatal("expected bootstrap admin email to be verified")
	}

	protected, err := service.isProtectedUser(ctx, record.ID)
	if err != nil {
		t.Fatalf("isProtectedUser() error = %v", err)
	}
	if !protected {
		t.Fatal("expected bootstrap admin to be protected by system role")
	}
}

func TestEnsureBootstrapAdminReactivatesExistingUser(t *testing.T) {
	service := newTestService(t)
	ctx := context.Background()

	record, err := service.CreateUser(ctx, CreateUserInput{
		Email:       "existing-bootstrap@example.com",
		DisplayName: "Existing",
		Password:    "old-password",
		Status:      store.UserStatusDisabled,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	oldHash := record.PasswordHash

	updated, err := service.EnsureBootstrapAdmin(ctx, BootstrapAdminInput{
		Email:       record.Email,
		DisplayName: "Bootstrap Existing",
		Password:    "new-password",
		RoleCode:    "system-admin",
	})
	if err != nil {
		t.Fatalf("EnsureBootstrapAdmin() error = %v", err)
	}
	if updated.Status != store.UserStatusActive {
		t.Fatalf("status = %q, want %q", updated.Status, store.UserStatusActive)
	}
	if updated.PasswordHash == oldHash {
		t.Fatal("expected bootstrap admin password hash to change")
	}

	protected, err := service.isProtectedUser(ctx, updated.ID)
	if err != nil {
		t.Fatalf("isProtectedUser() error = %v", err)
	}
	if !protected {
		t.Fatal("expected existing bootstrap admin to receive system role")
	}
}
