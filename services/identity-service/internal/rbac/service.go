package rbac

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"example.com/identity-service/internal/cache"
	"example.com/identity-service/internal/store"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const permissionCacheTTL = 2 * time.Minute

type Service struct {
	db    *gorm.DB
	redis *redis.Client
}

type permissionRow struct {
	Code string
}

type memberScope struct {
	UserID   int64
	TenantID int64
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
	if permissions, ok, err := s.loadCachedPermissions(ctx, userID, tenantID); err != nil {
		return nil, err
	} else if ok {
		return permissions, nil
	}

	var rows []permissionRow
	err := s.db.WithContext(ctx).
		Table("permissions").
		Select("DISTINCT permissions.code AS code").
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Joins("JOIN roles ON roles.id = role_permissions.role_id").
		Joins("JOIN member_roles ON member_roles.role_id = roles.id").
		Joins("JOIN tenant_members ON tenant_members.id = member_roles.member_id").
		Joins("JOIN users ON users.id = tenant_members.user_id").
		Where("users.id = ? AND tenant_members.tenant_id = ? AND roles.tenant_id = ?", userID, tenantID, tenantID).
		Where("roles.tenant_id = tenant_members.tenant_id").
		Where("users.status = ? AND tenant_members.status = ?", store.UserStatusActive, store.MemberStatusActive).
		Where("users.deleted_at IS NULL AND tenant_members.deleted_at IS NULL").
		Order("permissions.code ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	permissions := make([]string, 0, len(rows))
	for _, row := range rows {
		permissions = append(permissions, row.Code)
	}
	sort.Strings(permissions)

	if err := s.storeCachedPermissions(ctx, userID, tenantID, permissions); err != nil {
		return nil, err
	}
	return permissions, nil
}

func (s *Service) InvalidateUserTenantPermissions(ctx context.Context, userID, tenantID int64) error {
	if s.redis == nil {
		return nil
	}
	return s.redis.Del(ctx, cache.PermissionCacheKey(tenantID, userID)).Err()
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

	var scopes []memberScope
	if err := s.db.WithContext(ctx).
		Table("tenant_members").
		Select("tenant_members.user_id AS user_id, tenant_members.tenant_id AS tenant_id").
		Joins("JOIN member_roles ON member_roles.member_id = tenant_members.id").
		Where("member_roles.role_id = ?", roleID).
		Where("tenant_members.deleted_at IS NULL").
		Scan(&scopes).Error; err != nil {
		return err
	}

	for _, scope := range scopes {
		if err := s.InvalidateUserTenantPermissions(ctx, scope.UserID, scope.TenantID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) loadCachedPermissions(ctx context.Context, userID, tenantID int64) ([]string, bool, error) {
	if s.redis == nil {
		return nil, false, nil
	}

	value, err := s.redis.Get(ctx, cache.PermissionCacheKey(tenantID, userID)).Result()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	var permissions []string
	if err := json.Unmarshal([]byte(value), &permissions); err != nil {
		return nil, false, err
	}
	sort.Strings(permissions)
	return permissions, true, nil
}

func (s *Service) storeCachedPermissions(ctx context.Context, userID, tenantID int64, permissions []string) error {
	if s.redis == nil {
		return nil
	}

	payload, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, cache.PermissionCacheKey(tenantID, userID), payload, permissionCacheTTL).Err()
}
