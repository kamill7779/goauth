package tenant_test

import (
	"context"
	"testing"

	"example.com/identity-service/internal/audit"
	"github.com/alicebob/miniredis/v2"

	"example.com/identity-service/internal/cache"
	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/rbac"
	"example.com/identity-service/internal/store"
	"example.com/identity-service/internal/tenant"
)

func newTenantService(t *testing.T) *tenant.Service {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	mini := miniredis.RunT(t)
	redisClient, err := cache.OpenRedis(config.Config{
		RedisURL: "redis://" + mini.Addr() + "/0",
	})
	if err != nil {
		t.Fatalf("cache.OpenRedis() error = %v", err)
	}
	t.Cleanup(func() {
		_ = redisClient.Close()
	})

	service := tenant.NewService(db, rbac.NewService(db, redisClient))
	service.SetAuditRecorder(audit.NewService(db))
	return service
}

func TestCreateTenantAndAddMember(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	tenantRecord, err := service.CreateTenant(ctx, tenant.CreateTenantInput{
		Name: "Acme",
		Slug: "acme",
	})
	if err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}

	db := service.DB()
	user := store.User{
		Email:        "member@example.com",
		DisplayName:  "member",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("db.Create(user) error = %v", err)
	}

	member, err := service.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}
	if member.TenantID != tenantRecord.ID || member.UserID != user.ID {
		t.Fatalf("member = %#v, want tenant/user ids to match", member)
	}
}

func TestGrantAndRevokeRolePermissions(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	tenantRecord, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	role, err := service.CreateRole(ctx, tenant.CreateRoleInput{
		TenantID: tenantRecord.ID,
		Name:     "Admin",
		Code:     "admin",
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	db := service.DB()
	permission := store.Permission{Resource: "project", Action: "create", Code: "project:create"}
	if err := db.Create(&permission).Error; err != nil {
		t.Fatalf("db.Create(permission) error = %v", err)
	}

	if err := service.GrantPermissions(ctx, role.ID, []int64{permission.ID}); err != nil {
		t.Fatalf("GrantPermissions() error = %v", err)
	}
	if err := service.RevokePermission(ctx, role.ID, permission.ID); err != nil {
		t.Fatalf("RevokePermission() error = %v", err)
	}

	var count int64
	if err := db.Model(&store.RolePermission{}).
		Where("role_id = ? AND permission_id = ?", role.ID, permission.ID).
		Count(&count).Error; err != nil {
		t.Fatalf("count role permission: %v", err)
	}
	if count != 0 {
		t.Fatalf("role permission count = %d, want 0", count)
	}
}

func TestMembershipChangesWriteAuditLogs(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	tenantRecord, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	user := store.User{
		Email:        "member@example.com",
		DisplayName:  "member",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := service.DB().Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := service.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	}); err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}
	if err := service.RemoveMember(ctx, tenantRecord.ID, user.ID); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}

	var count int64
	if err := service.DB().Model(&store.AuditLog{}).
		Where("action IN ?", []string{audit.ActionTenantMembershipAdded, audit.ActionTenantMembershipRemoved}).
		Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 2 {
		t.Fatalf("membership audit log count = %d, want 2", count)
	}
}

func TestRoleAssignmentChangesWriteAuditLogs(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	user := store.User{
		Email:        "role@example.com",
		DisplayName:  "role",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := service.DB().Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	tenantRecord, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	member, err := service.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}
	role, err := service.CreateRole(ctx, tenant.CreateRoleInput{
		TenantID: tenantRecord.ID,
		Name:     "Admin",
		Code:     "admin",
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	if err := service.AssignRoles(ctx, member.ID, []int64{role.ID}); err != nil {
		t.Fatalf("AssignRoles() error = %v", err)
	}
	if err := service.RemoveRole(ctx, member.ID, role.ID); err != nil {
		t.Fatalf("RemoveRole() error = %v", err)
	}

	var count int64
	if err := service.DB().Model(&store.AuditLog{}).
		Where("action IN ?", []string{audit.ActionRoleAssigned, audit.ActionRoleRemoved}).
		Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 2 {
		t.Fatalf("role assignment audit log count = %d, want 2", count)
	}
}
