package tenant_test

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"goauth/services/identity-service/internal/audit"

	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/rbac"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
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

func TestAddMemberRestoresRemovedMember(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	tenantRecord, err := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	user := store.User{
		Email:        "readd@example.com",
		DisplayName:  "readd",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := service.DB().Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	first, err := service.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() first error = %v", err)
	}
	if err := service.RemoveMember(ctx, tenantRecord.ID, user.ID); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}

	second, err := service.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() second error = %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("restored member id = %d, want %d", second.ID, first.ID)
	}
	if second.DeletedAt.Valid {
		t.Fatal("restored member is still soft-deleted")
	}
}

func TestAddMemberRequiresActiveTenantAndUser(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	activeTenant, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	disabledTenant, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{
		Name:   "Disabled",
		Slug:   "disabled",
		Status: store.TenantStatusDisabled,
	})
	activeUser := store.User{
		Email:        "active@example.com",
		DisplayName:  "active",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	disabledUser := store.User{
		Email:        "disabled@example.com",
		DisplayName:  "disabled",
		PasswordHash: "hash",
		Status:       store.UserStatusDisabled,
	}
	if err := service.DB().Create(&activeUser).Error; err != nil {
		t.Fatalf("create active user: %v", err)
	}
	if err := service.DB().Create(&disabledUser).Error; err != nil {
		t.Fatalf("create disabled user: %v", err)
	}

	cases := []struct {
		name     string
		tenantID int64
		userID   int64
	}{
		{name: "missing tenant", tenantID: activeTenant.ID + disabledTenant.ID + 100, userID: activeUser.ID},
		{name: "disabled tenant", tenantID: disabledTenant.ID, userID: activeUser.ID},
		{name: "missing user", tenantID: activeTenant.ID, userID: activeUser.ID + disabledUser.ID + 100},
		{name: "disabled user", tenantID: activeTenant.ID, userID: disabledUser.ID},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.AddMember(ctx, tenant.AddMemberInput{
				TenantID: tt.tenantID,
				UserID:   tt.userID,
				Status:   store.MemberStatusActive,
			})
			if err == nil {
				t.Fatal("AddMember() error = nil, want validation error")
			}
		})
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

func TestCreateRoleRequiresActiveTenant(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	activeTenant, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	disabledTenant, _ := service.CreateTenant(ctx, tenant.CreateTenantInput{
		Name:   "Disabled",
		Slug:   "disabled",
		Status: store.TenantStatusDisabled,
	})

	cases := []struct {
		name     string
		tenantID int64
	}{
		{name: "missing tenant", tenantID: activeTenant.ID + disabledTenant.ID + 100},
		{name: "disabled tenant", tenantID: disabledTenant.ID},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.CreateRole(ctx, tenant.CreateRoleInput{
				TenantID: tt.tenantID,
				Name:     "Admin",
				Code:     "admin-" + tt.name,
			})
			if err == nil {
				t.Fatal("CreateRole() error = nil, want validation error")
			}
		})
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

func TestAssignRolesRejectsCrossTenantRoles(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	user := store.User{
		Email:        "cross-tenant@example.com",
		DisplayName:  "cross-tenant",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := service.DB().Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	tenantA, err := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Tenant A", Slug: "tenant-a"})
	if err != nil {
		t.Fatalf("CreateTenant(tenantA) error = %v", err)
	}
	tenantB, err := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Tenant B", Slug: "tenant-b"})
	if err != nil {
		t.Fatalf("CreateTenant(tenantB) error = %v", err)
	}

	member, err := service.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantA.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}
	role, err := service.CreateRole(ctx, tenant.CreateRoleInput{
		TenantID: tenantB.ID,
		Name:     "Other Tenant Admin",
		Code:     "other-admin",
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	err = service.AssignRoles(ctx, member.ID, []int64{role.ID})
	if err == nil {
		t.Fatal("AssignRoles() error = nil, want tenant mismatch error")
	}
	if !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("AssignRoles() error = %v, want tenant mismatch error", err)
	}

	var count int64
	if err := service.DB().Model(&store.MemberRole{}).
		Where("member_id = ? AND role_id = ?", member.ID, role.ID).
		Count(&count).Error; err != nil {
		t.Fatalf("count member roles: %v", err)
	}
	if count != 0 {
		t.Fatalf("member role count = %d, want 0", count)
	}
}

func TestTenantAndRoleLifecycleWritesAuditLogs(t *testing.T) {
	service := newTenantService(t)
	ctx := context.Background()

	tenantRecord, err := service.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}

	role, err := service.CreateRole(ctx, tenant.CreateRoleInput{
		TenantID: tenantRecord.ID,
		Name:     "Admin",
		Code:     "admin",
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	updatedName := "Acme Updated"
	updatedSlug := "acme-updated"
	updatedStatus := store.TenantStatusDisabled
	if _, err := service.UpdateTenant(ctx, tenantRecord.ID, tenant.UpdateTenantInput{
		Name:   &updatedName,
		Slug:   &updatedSlug,
		Status: &updatedStatus,
	}); err != nil {
		t.Fatalf("UpdateTenant() error = %v", err)
	}

	updatedRoleName := "Editor"
	updatedRoleCode := "editor"
	updatedRoleDescription := "Updated role"
	if _, err := service.UpdateRole(ctx, role.ID, tenant.UpdateRoleInput{
		Name:        &updatedRoleName,
		Code:        &updatedRoleCode,
		Description: &updatedRoleDescription,
	}); err != nil {
		t.Fatalf("UpdateRole() error = %v", err)
	}

	permission := store.Permission{Resource: "project", Action: "read", Code: "project:read"}
	if err := service.DB().Create(&permission).Error; err != nil {
		t.Fatalf("create permission: %v", err)
	}

	if err := service.GrantPermissions(ctx, role.ID, []int64{permission.ID}); err != nil {
		t.Fatalf("GrantPermissions() error = %v", err)
	}
	if err := service.RevokePermission(ctx, role.ID, permission.ID); err != nil {
		t.Fatalf("RevokePermission() error = %v", err)
	}
	if err := service.DeleteRole(ctx, role.ID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	actions := []string{
		"tenant_created",
		"tenant_updated",
		"role_created",
		"role_updated",
		"role_deleted",
		"role_permissions_granted",
		"role_permission_revoked",
	}

	var count int64
	if err := service.DB().Model(&store.AuditLog{}).
		Where("action IN ?", actions).
		Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != int64(len(actions)) {
		t.Fatalf("lifecycle audit log count = %d, want %d", count, len(actions))
	}
}
