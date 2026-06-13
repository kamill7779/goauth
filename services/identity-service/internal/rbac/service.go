// Package rbac implements role-based access control with a version-gated Redis
// cache. Permission lookups are resolved from live DB state; the cache is only
// trusted when its stored version matches the member's current permission_version.
package rbac

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

// permissionCacheTTL bounds staleness when the version-based invalidation path
// is missed (e.g., Redis flush, deployment race). 2 minutes is short enough for
// quick recovery yet long enough to absorb burst reads on hot users.
const permissionCacheTTL = 2 * time.Minute
const memberScopeBatchSize = 500

type Service struct {
	db    *gorm.DB
	redis *redis.Client
}

type memberScope struct {
	UserID   int64
	TenantID int64
}

type permissionCacheEntry struct {
	Version     int      `json:"version"`
	Permissions []string `json:"permissions"`
}

// NewService creates an RBAC Service. Pass nil for redisClient to disable caching.
//
// Call chain: main → NewService → Service
func NewService(db *gorm.DB, redisClient *redis.Client) *Service {
	return &Service{
		db:    db,
		redis: redisClient,
	}
}

// Can returns whether a user has a specific permission in a tenant.
//
// Call chain: check/checkBatch → Can → ListPermissions
func (s *Service) Can(ctx context.Context, userID, tenantID int64, permission string) (bool, error) {
	permissions, err := s.ListPermissions(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}

	for _, code := range permissions {
		if code == permission {
			return true, nil
		}
	}
	return false, nil
}

// ListPermissions returns the user's effective permission codes for a tenant.
// Cache flow: read cached version, re-fetch the live version from the member
// row, return the cache only when versions match. On miss/mismatch we read DB
// then re-check the version before writing back, so a concurrent role change
// can't be overwritten with stale data.
func (s *Service) ListPermissions(ctx context.Context, userID, tenantID int64) ([]string, error) {
	if permissions, cachedVersion, ok, err := s.loadCachedPermissions(ctx, userID, tenantID); err != nil {
		return nil, err
	} else if ok {
		currentVersion, active, err := s.permissionScopeVersion(ctx, userID, tenantID)
		if err != nil || !active {
			return []string{}, err
		}
		if cachedVersion == currentVersion {
			return permissions, nil
		}
	}

	initialVersion, active, err := s.permissionScopeVersion(ctx, userID, tenantID)
	if err != nil || !active {
		return []string{}, err
	}

	// Resolve permissions from live user/member state so membership changes and
	// role revocation are enforced independently from token claims.
	permissions, err := s.lookupPermissionCodes(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	sort.Strings(permissions)

	currentVersion, active, err := s.permissionScopeVersion(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if active && currentVersion == initialVersion {
		if err := s.storeCachedPermissions(ctx, userID, tenantID, currentVersion, permissions); err != nil {
			return nil, err
		}
	}
	return permissions, nil
}

// InvalidateUserTenantPermissions removes the cached permission entry for a
// (user, tenant) pair. No-op when Redis is nil.
//
// Call chain: tenant service mutating methods → InvalidateUserTenantPermissions → redis.Del
func (s *Service) InvalidateUserTenantPermissions(ctx context.Context, userID, tenantID int64) error {
	if s.redis == nil {
		return nil
	}
	_ = s.redis.Del(ctx, cache.PermissionCacheKey(tenantID, userID)).Err()
	return nil
}

// InvalidateMemberPermissions resolves a member ID to (user, tenant) and
// invalidates that pair's cache entry.
//
// Call chain: (external callers) → InvalidateMemberPermissions → db.First + InvalidateUserTenantPermissions
func (s *Service) InvalidateMemberPermissions(ctx context.Context, memberID int64) error {
	if s.redis == nil {
		return nil
	}

	var member store.TenantMember
	if err := s.db.WithContext(ctx).First(&member, memberID).Error; err != nil {
		return err
	}
	return s.InvalidateUserTenantPermissions(ctx, member.UserID, member.TenantID)
}

// InvalidateRolePermissions invalidates the cache for every member who holds
// the given role, processing in batches of memberScopeBatchSize.
//
// Call chain: (external callers) → InvalidateRolePermissions → memberIDsForRole + memberScopesByIDs + InvalidateUserTenantPermissions
func (s *Service) InvalidateRolePermissions(ctx context.Context, roleID int64) error {
	if s.redis == nil {
		return nil
	}

	memberIDs, err := s.memberIDsForRole(ctx, roleID)
	if err != nil {
		return err
	}
	for start := 0; start < len(memberIDs); start += memberScopeBatchSize {
		end := start + memberScopeBatchSize
		if end > len(memberIDs) {
			end = len(memberIDs)
		}
		scopes, err := s.memberScopesByIDs(ctx, memberIDs[start:end])
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			if err := s.InvalidateUserTenantPermissions(ctx, scope.UserID, scope.TenantID); err != nil {
				return err
			}
		}
	}
	return nil
}

// InvalidateTenantPermissions invalidates the cache for every active member
// of a tenant, processing in batches.
//
// Call chain: UpdateTenant → InvalidateTenantPermissions → db.Pluck + memberScopesByIDs + InvalidateUserTenantPermissions
func (s *Service) InvalidateTenantPermissions(ctx context.Context, tenantID int64) error {
	if s.redis == nil {
		return nil
	}

	var memberIDs []int64
	if err := s.db.WithContext(ctx).
		Model(&store.TenantMember{}).
		Where("tenant_id = ? AND deleted_at IS NULL", tenantID).
		Pluck("id", &memberIDs).Error; err != nil {
		return err
	}

	for start := 0; start < len(memberIDs); start += memberScopeBatchSize {
		end := start + memberScopeBatchSize
		if end > len(memberIDs) {
			end = len(memberIDs)
		}
		scopes, err := s.memberScopesByIDs(ctx, memberIDs[start:end])
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			if err := s.InvalidateUserTenantPermissions(ctx, scope.UserID, scope.TenantID); err != nil {
				return err
			}
		}
	}
	return nil
}

// lookupPermissionCodes resolves a user's effective permission codes for a
// tenant by walking: active member IDs → role IDs → permission IDs → codes.
//
// Call chain: ListPermissions → lookupPermissionCodes → activeMemberIDsForUserTenant → roleIDsForMembersInTenant → permissionIDsForRoles → permissionCodesByIDs
func (s *Service) lookupPermissionCodes(ctx context.Context, userID, tenantID int64) ([]string, error) {
	memberIDs, err := s.activeMemberIDsForUserTenant(ctx, userID, tenantID)
	if err != nil || len(memberIDs) == 0 {
		return []string{}, err
	}

	roleIDs, err := s.roleIDsForMembersInTenant(ctx, memberIDs, tenantID)
	if err != nil || len(roleIDs) == 0 {
		return []string{}, err
	}

	permissionIDs, err := s.permissionIDsForRoles(ctx, roleIDs)
	if err != nil || len(permissionIDs) == 0 {
		return []string{}, err
	}

	return s.permissionCodesByIDs(ctx, permissionIDs)
}

// activeMemberIDsForUserTenant returns active member IDs for a user in a tenant.
// Returns nil if the tenant or user is inactive/deleted.
//
// Call chain: lookupPermissionCodes → activeMemberIDsForUserTenant → db queries
func (s *Service) activeMemberIDsForUserTenant(ctx context.Context, userID, tenantID int64) ([]int64, error) {
	if !s.activeTenantExists(ctx, tenantID) {
		return nil, nil
	}

	var userCount int64
	if err := s.db.WithContext(ctx).
		Model(&store.User{}).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		Count(&userCount).Error; err != nil {
		return nil, err
	}
	if userCount == 0 {
		return nil, nil
	}

	var memberIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ? AND status = ? AND deleted_at IS NULL", tenantID, userID, store.MemberStatusActive).
		Pluck("id", &memberIDs).Error
	return memberIDs, err
}

// activeTenantExists returns true when a tenant exists, is active, and is not deleted.
func (s *Service) activeTenantExists(ctx context.Context, tenantID int64) bool {
	var count int64
	err := s.db.WithContext(ctx).
		Model(&store.Tenant{}).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, store.TenantStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

// permissionScopeVersion returns the max permission_version and whether any
// active membership exists for a (user, tenant) pair.
//
// Call chain: ListPermissions → permissionScopeVersion → db queries
func (s *Service) permissionScopeVersion(ctx context.Context, userID, tenantID int64) (int, bool, error) {
	if !s.activeTenantExists(ctx, tenantID) {
		return 0, false, nil
	}

	var userCount int64
	if err := s.db.WithContext(ctx).
		Model(&store.User{}).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		Count(&userCount).Error; err != nil {
		return 0, false, err
	}
	if userCount == 0 {
		return 0, false, nil
	}

	var scope struct {
		Version int
		Count   int64
	}
	if err := s.db.WithContext(ctx).
		Model(&store.TenantMember{}).
		Select("COALESCE(MAX(permission_version), 0) AS version, COUNT(*) AS count").
		Where("tenant_id = ? AND user_id = ? AND status = ? AND deleted_at IS NULL", tenantID, userID, store.MemberStatusActive).
		Scan(&scope).Error; err != nil {
		return 0, false, err
	}
	return scope.Version, scope.Count > 0, nil
}

// roleIDsForMembersInTenant returns distinct role IDs assigned to the given
// members that also belong to the specified tenant.
//
// Call chain: lookupPermissionCodes → roleIDsForMembersInTenant → db queries
func (s *Service) roleIDsForMembersInTenant(ctx context.Context, memberIDs []int64, tenantID int64) ([]int64, error) {
	var assignedRoleIDs []int64
	if err := s.db.WithContext(ctx).
		Model(&store.MemberRole{}).
		Distinct("role_id").
		Where("member_id IN ?", memberIDs).
		Pluck("role_id", &assignedRoleIDs).Error; err != nil {
		return nil, err
	}
	if len(assignedRoleIDs) == 0 {
		return nil, nil
	}

	var roleIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.Role{}).
		Where("tenant_id = ? AND id IN ?", tenantID, assignedRoleIDs).
		Pluck("id", &roleIDs).Error
	return roleIDs, err
}

// permissionIDsForRoles returns distinct permission IDs assigned to any of the given roles.
//
// Call chain: lookupPermissionCodes → permissionIDsForRoles → db.Pluck
func (s *Service) permissionIDsForRoles(ctx context.Context, roleIDs []int64) ([]int64, error) {
	var permissionIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.RolePermission{}).
		Distinct("permission_id").
		Where("role_id IN ?", roleIDs).
		Pluck("permission_id", &permissionIDs).Error
	return permissionIDs, err
}

// permissionCodesByIDs returns distinct, sorted permission codes for the given IDs.
//
// Call chain: lookupPermissionCodes → permissionCodesByIDs → db.Pluck
func (s *Service) permissionCodesByIDs(ctx context.Context, permissionIDs []int64) ([]string, error) {
	permissions := []string{}
	err := s.db.WithContext(ctx).
		Model(&store.Permission{}).
		Distinct("code").
		Where("id IN ?", permissionIDs).
		Order("code ASC").
		Pluck("code", &permissions).Error
	if err != nil {
		return nil, err
	}
	sort.Strings(permissions)
	return permissions, nil
}

// memberIDsForRole returns member IDs that hold the given role.
//
// Call chain: InvalidateRolePermissions → memberIDsForRole → db.Pluck
func (s *Service) memberIDsForRole(ctx context.Context, roleID int64) ([]int64, error) {
	var memberIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.MemberRole{}).
		Where("role_id = ?", roleID).
		Pluck("member_id", &memberIDs).Error
	return memberIDs, err
}

// memberScopesByIDs returns (user_id, tenant_id) pairs for the given member IDs.
//
// Call chain: InvalidateRolePermissions/InvalidateTenantPermissions → memberScopesByIDs → db.Scan
func (s *Service) memberScopesByIDs(ctx context.Context, memberIDs []int64) ([]memberScope, error) {
	if len(memberIDs) == 0 {
		return nil, nil
	}

	var scopes []memberScope
	err := s.db.WithContext(ctx).
		Model(&store.TenantMember{}).
		Select("user_id, tenant_id").
		Where("id IN ? AND deleted_at IS NULL", memberIDs).
		Scan(&scopes).Error
	return scopes, err
}

// loadCachedPermissions reads the Redis cache for a (user, tenant) pair.
// Returns (permissions, version, found, error). No-op when Redis is nil.
//
// Call chain: ListPermissions → loadCachedPermissions → redis.Get
func (s *Service) loadCachedPermissions(ctx context.Context, userID, tenantID int64) ([]string, int, bool, error) {
	if s.redis == nil {
		return nil, 0, false, nil
	}

	value, err := s.redis.Get(ctx, cache.PermissionCacheKey(tenantID, userID)).Result()
	if err == redis.Nil {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, nil
	}

	var entry permissionCacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil || entry.Permissions == nil {
		return nil, 0, false, nil
	}
	permissions := entry.Permissions
	sort.Strings(permissions)
	return permissions, entry.Version, true, nil
}

// storeCachedPermissions writes a permission snapshot to Redis with a TTL.
// No-op when Redis is nil.
//
// Call chain: ListPermissions → storeCachedPermissions → redis.Set
func (s *Service) storeCachedPermissions(ctx context.Context, userID, tenantID int64, version int, permissions []string) error {
	if s.redis == nil {
		return nil
	}

	payload, err := json.Marshal(permissionCacheEntry{
		Version:     version,
		Permissions: permissions,
	})
	if err != nil {
		return err
	}
	_ = s.redis.Set(ctx, cache.PermissionCacheKey(tenantID, userID), payload, permissionCacheTTL).Err()
	return nil
}
