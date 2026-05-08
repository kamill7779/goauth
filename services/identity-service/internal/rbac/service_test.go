package rbac_test

import (
	"context"
	"slices"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"gorm.io/gorm"

	"example.com/identity-service/internal/cache"
	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/rbac"
	"example.com/identity-service/internal/store"
	"example.com/identity-service/internal/tenant"
)

type testEnv struct {
	db     *gorm.DB
	rbac   *rbac.Service
	tenant *tenant.Service
}

func newTestEnv(t *testing.T) *testEnv {
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

	rbacService := rbac.NewService(db, redisClient)
	tenantService := tenant.NewService(db, rbacService)

	return &testEnv{
		db:     db,
		rbac:   rbacService,
		tenant: tenantService,
	}
}

func createUser(t *testing.T, db *gorm.DB, email string, status string) store.User {
	t.Helper()

	user := store.User{
		Email:        email,
		DisplayName:  email,
		PasswordHash: "hash",
		Status:       status,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("db.Create(user) error = %v", err)
	}
	return user
}

func createPermission(t *testing.T, db *gorm.DB, code string) store.Permission {
	t.Helper()

	permission := store.Permission{
		Resource: code,
		Action:   "use",
		Code:     code,
	}
	if err := db.Create(&permission).Error; err != nil {
		t.Fatalf("db.Create(permission) error = %v", err)
	}
	return permission
}

func TestMemberRoleGrantsPermission(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	user := createUser(t, env.db, "member@example.com", store.UserStatusActive)
	tenantRecord, err := env.tenant.CreateTenant(ctx, tenant.CreateTenantInput{
		Name: "Acme",
		Slug: "acme",
	})
	if err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	member, err := env.tenant.AddMember(ctx, tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}
	role, err := env.tenant.CreateRole(ctx, tenant.CreateRoleInput{
		TenantID: tenantRecord.ID,
		Name:     "Admin",
		Code:     "admin",
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	permission := createPermission(t, env.db, "project:create")
	if err := env.tenant.GrantPermissions(ctx, role.ID, []int64{permission.ID}); err != nil {
		t.Fatalf("GrantPermissions() error = %v", err)
	}
	if err := env.tenant.AssignRoles(ctx, member.ID, []int64{role.ID}); err != nil {
		t.Fatalf("AssignRoles() error = %v", err)
	}

	allowed, err := env.rbac.Can(ctx, user.ID, tenantRecord.ID, "project:create")
	if err != nil {
		t.Fatalf("Can() error = %v", err)
	}
	if !allowed {
		t.Fatal("expected permission to be granted")
	}

	permissions, err := env.rbac.ListPermissions(ctx, user.ID, tenantRecord.ID)
	if err != nil {
		t.Fatalf("ListPermissions() error = %v", err)
	}
	if len(permissions) != 1 || permissions[0] != "project:create" {
		t.Fatalf("permissions = %#v, want [project:create]", permissions)
	}
}

func TestRemovingRoleRemovesAccess(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	user := createUser(t, env.db, "member@example.com", store.UserStatusActive)
	tenantRecord, _ := env.tenant.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	member, _ := env.tenant.AddMember(ctx, tenant.AddMemberInput{TenantID: tenantRecord.ID, UserID: user.ID, Status: store.MemberStatusActive})
	role, _ := env.tenant.CreateRole(ctx, tenant.CreateRoleInput{TenantID: tenantRecord.ID, Name: "Admin", Code: "admin"})
	permission := createPermission(t, env.db, "project:create")
	_ = env.tenant.GrantPermissions(ctx, role.ID, []int64{permission.ID})
	_ = env.tenant.AssignRoles(ctx, member.ID, []int64{role.ID})

	if _, err := env.rbac.ListPermissions(ctx, user.ID, tenantRecord.ID); err != nil {
		t.Fatalf("warm ListPermissions() error = %v", err)
	}
	if err := env.tenant.RemoveRole(ctx, member.ID, role.ID); err != nil {
		t.Fatalf("RemoveRole() error = %v", err)
	}

	allowed, err := env.rbac.Can(ctx, user.ID, tenantRecord.ID, "project:create")
	if err != nil {
		t.Fatalf("Can() error = %v", err)
	}
	if allowed {
		t.Fatal("expected permission to be removed")
	}
}

func TestUserCanHaveDifferentRolesAcrossTenants(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	user := createUser(t, env.db, "shared@example.com", store.UserStatusActive)
	tenantA, _ := env.tenant.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Tenant A", Slug: "tenant-a"})
	tenantB, _ := env.tenant.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Tenant B", Slug: "tenant-b"})
	memberA, _ := env.tenant.AddMember(ctx, tenant.AddMemberInput{TenantID: tenantA.ID, UserID: user.ID, Status: store.MemberStatusActive})
	memberB, _ := env.tenant.AddMember(ctx, tenant.AddMemberInput{TenantID: tenantB.ID, UserID: user.ID, Status: store.MemberStatusActive})
	roleA, _ := env.tenant.CreateRole(ctx, tenant.CreateRoleInput{TenantID: tenantA.ID, Name: "Reader", Code: "reader"})
	roleB, _ := env.tenant.CreateRole(ctx, tenant.CreateRoleInput{TenantID: tenantB.ID, Name: "Writer", Code: "writer"})
	readPermission := createPermission(t, env.db, "project:read")
	writePermission := createPermission(t, env.db, "project:write")
	_ = env.tenant.GrantPermissions(ctx, roleA.ID, []int64{readPermission.ID})
	_ = env.tenant.GrantPermissions(ctx, roleB.ID, []int64{writePermission.ID})
	_ = env.tenant.AssignRoles(ctx, memberA.ID, []int64{roleA.ID})
	_ = env.tenant.AssignRoles(ctx, memberB.ID, []int64{roleB.ID})

	permsA, err := env.rbac.ListPermissions(ctx, user.ID, tenantA.ID)
	if err != nil {
		t.Fatalf("ListPermissions(tenantA) error = %v", err)
	}
	permsB, err := env.rbac.ListPermissions(ctx, user.ID, tenantB.ID)
	if err != nil {
		t.Fatalf("ListPermissions(tenantB) error = %v", err)
	}
	if !slices.Equal(permsA, []string{"project:read"}) {
		t.Fatalf("permsA = %#v, want [project:read]", permsA)
	}
	if !slices.Equal(permsB, []string{"project:write"}) {
		t.Fatalf("permsB = %#v, want [project:write]", permsB)
	}
}

func TestPermissionCacheInvalidatesAfterRoleChanges(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	user := createUser(t, env.db, "cache@example.com", store.UserStatusActive)
	tenantRecord, _ := env.tenant.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	member, _ := env.tenant.AddMember(ctx, tenant.AddMemberInput{TenantID: tenantRecord.ID, UserID: user.ID, Status: store.MemberStatusActive})
	role, _ := env.tenant.CreateRole(ctx, tenant.CreateRoleInput{TenantID: tenantRecord.ID, Name: "Editor", Code: "editor"})
	readPermission := createPermission(t, env.db, "project:read")
	writePermission := createPermission(t, env.db, "project:write")
	_ = env.tenant.GrantPermissions(ctx, role.ID, []int64{readPermission.ID})
	_ = env.tenant.AssignRoles(ctx, member.ID, []int64{role.ID})

	perms, err := env.rbac.ListPermissions(ctx, user.ID, tenantRecord.ID)
	if err != nil {
		t.Fatalf("warm ListPermissions() error = %v", err)
	}
	if !slices.Equal(perms, []string{"project:read"}) {
		t.Fatalf("perms = %#v, want [project:read]", perms)
	}

	if err := env.tenant.GrantPermissions(ctx, role.ID, []int64{writePermission.ID}); err != nil {
		t.Fatalf("GrantPermissions() second error = %v", err)
	}

	perms, err = env.rbac.ListPermissions(ctx, user.ID, tenantRecord.ID)
	if err != nil {
		t.Fatalf("ListPermissions() after invalidate error = %v", err)
	}
	if !slices.Equal(perms, []string{"project:read", "project:write"}) {
		t.Fatalf("perms after invalidate = %#v, want [project:read project:write]", perms)
	}
}

func TestDisabledUsersAndMembersFailChecks(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	disabledUser := createUser(t, env.db, "disabled-user@example.com", store.UserStatusDisabled)
	activeUser := createUser(t, env.db, "disabled-member@example.com", store.UserStatusActive)
	tenantRecord, _ := env.tenant.CreateTenant(ctx, tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	disabledUserMember, _ := env.tenant.AddMember(ctx, tenant.AddMemberInput{TenantID: tenantRecord.ID, UserID: disabledUser.ID, Status: store.MemberStatusActive})
	disabledMember, _ := env.tenant.AddMember(ctx, tenant.AddMemberInput{TenantID: tenantRecord.ID, UserID: activeUser.ID, Status: store.MemberStatusDisabled})
	role, _ := env.tenant.CreateRole(ctx, tenant.CreateRoleInput{TenantID: tenantRecord.ID, Name: "Admin", Code: "admin"})
	permission := createPermission(t, env.db, "project:create")
	_ = env.tenant.GrantPermissions(ctx, role.ID, []int64{permission.ID})
	_ = env.tenant.AssignRoles(ctx, disabledUserMember.ID, []int64{role.ID})
	_ = env.tenant.AssignRoles(ctx, disabledMember.ID, []int64{role.ID})

	allowed, err := env.rbac.Can(ctx, disabledUser.ID, tenantRecord.ID, "project:create")
	if err != nil {
		t.Fatalf("Can(disabled user) error = %v", err)
	}
	if allowed {
		t.Fatal("expected disabled user to fail permission check")
	}

	allowed, err = env.rbac.Can(ctx, activeUser.ID, tenantRecord.ID, "project:create")
	if err != nil {
		t.Fatalf("Can(disabled member) error = %v", err)
	}
	if allowed {
		t.Fatal("expected disabled member to fail permission check")
	}
}
