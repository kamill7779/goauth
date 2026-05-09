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

func NewService(db *gorm.DB, redisClient *redis.Client) *Service {
	return &Service{
		db:    db,
		redis: redisClient,
	}
}

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
	if active {
		if err := s.storeCachedPermissions(ctx, userID, tenantID, currentVersion, permissions); err != nil {
			return nil, err
		}
	}
	return permissions, nil
}

func (s *Service) InvalidateUserTenantPermissions(ctx context.Context, userID, tenantID int64) error {
	if s.redis == nil {
		return nil
	}
	_ = s.redis.Del(ctx, cache.PermissionCacheKey(tenantID, userID)).Err()
	return nil
}

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

func (s *Service) activeTenantExists(ctx context.Context, tenantID int64) bool {
	var count int64
	err := s.db.WithContext(ctx).
		Model(&store.Tenant{}).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, store.TenantStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

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

func (s *Service) permissionIDsForRoles(ctx context.Context, roleIDs []int64) ([]int64, error) {
	var permissionIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.RolePermission{}).
		Distinct("permission_id").
		Where("role_id IN ?", roleIDs).
		Pluck("permission_id", &permissionIDs).Error
	return permissionIDs, err
}

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

func (s *Service) memberIDsForRole(ctx context.Context, roleID int64) ([]int64, error) {
	var memberIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.MemberRole{}).
		Where("role_id = ?", roleID).
		Pluck("member_id", &memberIDs).Error
	return memberIDs, err
}

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
