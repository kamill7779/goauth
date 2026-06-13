// Package tenant manages multi-tenant lifecycle: tenant CRUD, membership,
// role/permission assignment, and permission-version-based cache invalidation.
package tenant

import (
	"context"
	"fmt"
	"strconv"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/rbac"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	auditActionTenantCreated          = "tenant_created"
	auditActionTenantUpdated          = "tenant_updated"
	auditActionRoleCreated            = "role_created"
	auditActionRoleUpdated            = "role_updated"
	auditActionRoleDeleted            = "role_deleted"
	auditActionRolePermissionsGranted = "role_permissions_granted"
	auditActionRolePermissionRevoked  = "role_permission_revoked"
	auditTargetTypeTenant             = "tenant"
)

type Service struct {
	db    *gorm.DB
	rbac  *rbac.Service
	audit audit.Recorder
}

type permissionCacheScope struct {
	UserID   int64
	TenantID int64
}

type CreateTenantInput struct {
	Name   string `json:"name"`
	Slug   string `json:"slug"`
	Status string `json:"status"`
}

type UpdateTenantInput struct {
	Name   *string `json:"name"`
	Slug   *string `json:"slug"`
	Status *string `json:"status"`
}

type AddMemberInput struct {
	TenantID int64  `json:"tenant_id"`
	UserID   int64  `json:"user_id"`
	Status   string `json:"status"`
}

type CreateRoleInput struct {
	TenantID    int64  `json:"tenant_id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	IsSystem    bool   `json:"is_system"`
}

type UpdateRoleInput struct {
	Name        *string `json:"name"`
	Code        *string `json:"code"`
	Description *string `json:"description"`
	IsSystem    *bool   `json:"is_system"`
}

// NewService creates a tenant Service. Use SetDependencies to inject an audit recorder.
//
// Call chain: main → NewService → Service
func NewService(db *gorm.DB, rbacService *rbac.Service) *Service {
	return &Service{
		db:    db,
		rbac:  rbacService,
		audit: audit.NoopRecorder{},
	}
}

// SetDependencies injects optional collaborators (currently the audit recorder).
//
// Call chain: main/wire → SetDependencies → Service.audit
func (s *Service) SetDependencies(r audit.Recorder) {
	s.audit = r
	if s.audit == nil {
		s.audit = audit.NoopRecorder{}
	}
}

// SetAuditRecorder is deprecated; use SetDependencies instead.
func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

// DB returns the underlying *gorm.DB for consumers that need raw queries.
func (s *Service) DB() *gorm.DB {
	return s.db
}

// ListTenants returns all tenants ordered by ID.
//
// Call chain: (external consumers) → ListTenants → db.Find
func (s *Service) ListTenants(ctx context.Context) ([]store.Tenant, error) {
	var tenants []store.Tenant
	err := s.db.WithContext(ctx).Order("id ASC").Find(&tenants).Error
	return tenants, err
}

// CreateTenant creates a tenant, defaulting status to active when empty.
//
// Call chain: createTenant → CreateTenant → db.Create + audit.Record
func (s *Service) CreateTenant(ctx context.Context, input CreateTenantInput) (*store.Tenant, error) {
	status := input.Status
	if status == "" {
		status = store.TenantStatusActive
	}

	record := &store.Tenant{
		Name:   input.Name,
		Slug:   input.Slug,
		Status: status,
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, err
	}
	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    record.ID,
		Action:      auditActionTenantCreated,
		TargetType:  auditTargetTypeTenant,
		TargetID:    strconv.FormatInt(record.ID, 10),
		Metadata: map[string]any{
			"name":   record.Name,
			"slug":   record.Slug,
			"status": record.Status,
		},
	}); err != nil {
		return nil, err
	}
	return record, nil
}

// UpdateTenant patch-updates a tenant. When status changes, it bumps permission
// versions and invalidates the RBAC cache for that tenant.
//
// Call chain: updateTenant → UpdateTenant → db.Transaction + bumpTenantPermissionVersions + rbac.InvalidateTenantPermissions + audit.Record
func (s *Service) UpdateTenant(ctx context.Context, id int64, input UpdateTenantInput) (*store.Tenant, error) {
	updates := map[string]any{}
	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.Slug != nil {
		updates["slug"] = *input.Slug
	}
	if input.Status != nil {
		updates["status"] = *input.Status
	}
	if len(updates) > 0 {
		if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&store.Tenant{}).Where("id = ?", id).Updates(updates).Error; err != nil {
				return err
			}
			if input.Status != nil {
				return s.bumpTenantPermissionVersions(ctx, tx, id)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if input.Status != nil && s.rbac != nil {
			_ = s.rbac.InvalidateTenantPermissions(ctx, id)
		}
	}

	var record store.Tenant
	if err := s.db.WithContext(ctx).First(&record, id).Error; err != nil {
		return nil, err
	}
	if len(updates) > 0 {
		if err := s.audit.Record(ctx, audit.Entry{
			ActorUserID: 0,
			TenantID:    record.ID,
			Action:      auditActionTenantUpdated,
			TargetType:  auditTargetTypeTenant,
			TargetID:    strconv.FormatInt(record.ID, 10),
			Metadata:    updates,
		}); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

// AddMember adds a user to a tenant. Restores soft-deleted memberships when
// they exist instead of creating duplicates.
//
// Call chain: addMember/bulkAddUsersToTenant → AddMember → ensureActiveTenant + ensureActiveUser + db.Create/restore + recordMembershipAdded
func (s *Service) AddMember(ctx context.Context, input AddMemberInput) (*store.TenantMember, error) {
	status := input.Status
	if status == "" {
		status = store.MemberStatusActive
	}

	if err := s.ensureActiveTenant(ctx, input.TenantID); err != nil {
		return nil, err
	}
	if err := s.ensureActiveUser(ctx, input.UserID); err != nil {
		return nil, err
	}

	var existing store.TenantMember
	err := s.db.WithContext(ctx).
		Unscoped().
		Where("tenant_id = ? AND user_id = ?", input.TenantID, input.UserID).
		First(&existing).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if err == nil && existing.DeletedAt.Valid {
		if err := s.db.WithContext(ctx).
			Unscoped().
			Model(&store.TenantMember{}).
			Where("id = ?", existing.ID).
			Updates(map[string]any{
				"status":     status,
				"deleted_at": nil,
			}).Error; err != nil {
			return nil, err
		}
		var restored store.TenantMember
		if err := s.db.WithContext(ctx).First(&restored, existing.ID).Error; err != nil {
			return nil, err
		}
		if err := s.recordMembershipAdded(ctx, input.TenantID, &restored); err != nil {
			return nil, err
		}
		return &restored, nil
	}

	member := &store.TenantMember{
		TenantID: input.TenantID,
		UserID:   input.UserID,
		Status:   status,
	}
	if err := s.db.WithContext(ctx).Create(member).Error; err != nil {
		return nil, err
	}
	if err := s.recordMembershipAdded(ctx, input.TenantID, member); err != nil {
		return nil, err
	}
	return member, nil
}

// RemoveMember soft-deletes all memberships for a user in a tenant, removes
// their role assignments, bumps permission versions, and invalidates cache.
//
// Call chain: removeMember/bulkRemoveUsersFromTenant → RemoveMember → db.Transaction + bumpPermissionScopes + invalidatePermissionScopes + audit.Record
func (s *Service) RemoveMember(ctx context.Context, tenantID, userID int64) error {
	var members []store.TenantMember
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Find(&members).Error; err != nil {
		return err
	}

	scopes := make([]permissionCacheScope, 0, len(members))
	for _, member := range members {
		scopes = append(scopes, permissionCacheScope{UserID: member.UserID, TenantID: member.TenantID})
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.bumpPermissionScopes(ctx, tx, scopes); err != nil {
			return err
		}
		for _, member := range members {
			if err := tx.Where("member_id = ?", member.ID).Delete(&store.MemberRole{}).Error; err != nil {
				return err
			}
		}
		return tx.Where("tenant_id = ? AND user_id = ?", tenantID, userID).Delete(&store.TenantMember{}).Error
	}); err != nil {
		return err
	}
	if err := s.invalidatePermissionScopes(ctx, scopes); err != nil {
		return err
	}

	for _, member := range members {
		if err := s.audit.Record(ctx, audit.Entry{
			ActorUserID: 0,
			TenantID:    tenantID,
			Action:      audit.ActionTenantMembershipRemoved,
			TargetType:  audit.TargetTypeTenantMember,
			TargetID:    strconv.FormatInt(member.ID, 10),
			Metadata: map[string]any{
				"user_id": member.UserID,
			},
		}); err != nil {
			return err
		}
	}

	return nil
}

// ListRoles returns roles, optionally filtered by tenant ID.
//
// Call chain: (external consumers) → ListRoles → db.Find
func (s *Service) ListRoles(ctx context.Context, tenantID int64) ([]store.Role, error) {
	var roles []store.Role
	query := s.db.WithContext(ctx).Order("id ASC")
	if tenantID != 0 {
		query = query.Where("tenant_id = ?", tenantID)
	}
	err := query.Find(&roles).Error
	return roles, err
}

// CreateRole creates a role in a tenant after verifying the tenant is active.
//
// Call chain: createRole → CreateRole → ensureActiveTenant + db.Create + audit.Record
func (s *Service) CreateRole(ctx context.Context, input CreateRoleInput) (*store.Role, error) {
	if err := s.ensureActiveTenant(ctx, input.TenantID); err != nil {
		return nil, err
	}

	role := &store.Role{
		TenantID:    input.TenantID,
		Name:        input.Name,
		Code:        input.Code,
		Description: input.Description,
		IsSystem:    input.IsSystem,
	}
	if err := s.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, err
	}
	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    role.TenantID,
		Action:      auditActionRoleCreated,
		TargetType:  audit.TargetTypeRole,
		TargetID:    strconv.FormatInt(role.ID, 10),
		Metadata: map[string]any{
			"name":        role.Name,
			"code":        role.Code,
			"description": role.Description,
			"is_system":   role.IsSystem,
		},
	}); err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRole patch-updates a role's name, code, description, or system flag.
//
// Call chain: updateRole → UpdateRole → db.Updates + audit.Record
func (s *Service) UpdateRole(ctx context.Context, id int64, input UpdateRoleInput) (*store.Role, error) {
	updates := map[string]any{}
	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.Code != nil {
		updates["code"] = *input.Code
	}
	if input.Description != nil {
		updates["description"] = *input.Description
	}
	if input.IsSystem != nil {
		updates["is_system"] = *input.IsSystem
	}
	if len(updates) > 0 {
		if err := s.db.WithContext(ctx).Model(&store.Role{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return nil, err
		}
	}

	var role store.Role
	if err := s.db.WithContext(ctx).First(&role, id).Error; err != nil {
		return nil, err
	}
	if len(updates) > 0 {
		if err := s.audit.Record(ctx, audit.Entry{
			ActorUserID: 0,
			TenantID:    role.TenantID,
			Action:      auditActionRoleUpdated,
			TargetType:  audit.TargetTypeRole,
			TargetID:    strconv.FormatInt(role.ID, 10),
			Metadata:    updates,
		}); err != nil {
			return nil, err
		}
	}
	return &role, nil
}

// DeleteRole removes a role, its permissions, its member assignments, bumps
// the whole tenant's permission versions, and invalidates caches.
//
// Call chain: deleteRole → DeleteRole → db.Transaction (delete RolePermission + MemberRole + Role) + bumpTenantPermissionVersions + invalidatePermissionScopes + audit.Record
func (s *Service) DeleteRole(ctx context.Context, id int64) error {
	var role store.Role
	if err := s.db.WithContext(ctx).First(&role, id).Error; err != nil {
		return err
	}

	scopes, err := s.permissionCacheScopesForRole(ctx, id)
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", id).Delete(&store.RolePermission{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", id).Delete(&store.MemberRole{}).Error; err != nil {
			return err
		}
		// Deleting a role is rare and security-sensitive; bump the whole tenant
		// so concurrent assignments cannot leave version-valid stale grants.
		if err := s.bumpTenantPermissionVersions(ctx, tx, role.TenantID); err != nil {
			return err
		}
		return tx.Delete(&store.Role{}, id).Error
	}); err != nil {
		return err
	}
	if err := s.invalidatePermissionScopes(ctx, scopes); err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    role.TenantID,
		Action:      auditActionRoleDeleted,
		TargetType:  audit.TargetTypeRole,
		TargetID:    strconv.FormatInt(role.ID, 10),
		Metadata: map[string]any{
			"name": role.Name,
			"code": role.Code,
		},
	})
}

// GrantPermissions assigns permissions to a role (idempotent on conflict).
// Bumps permission versions and invalidates caches for affected members.
//
// Call chain: grantPermissions → GrantPermissions → db.Transaction + bumpRolePermissionScopes + invalidatePermissionScopes + audit.Record
func (s *Service) GrantPermissions(ctx context.Context, roleID int64, permissionIDs []int64) error {
	if len(permissionIDs) == 0 {
		return nil
	}

	role, err := s.roleByID(ctx, roleID)
	if err != nil {
		return err
	}
	scopes, err := s.permissionCacheScopesForRole(ctx, roleID)
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, permissionID := range permissionIDs {
			record := store.RolePermission{
				RoleID:       roleID,
				PermissionID: permissionID,
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&record).Error; err != nil {
				return err
			}
		}
		return s.bumpRolePermissionScopes(ctx, tx, roleID)
	}); err != nil {
		return err
	}
	if err := s.invalidatePermissionScopes(ctx, scopes); err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    role.TenantID,
		Action:      auditActionRolePermissionsGranted,
		TargetType:  audit.TargetTypeRole,
		TargetID:    strconv.FormatInt(role.ID, 10),
		Metadata: map[string]any{
			"permission_ids": permissionIDs,
		},
	})
}

// RevokePermission removes a single permission from a role, bumps versions,
// and invalidates caches.
//
// Call chain: revokePermission → RevokePermission → db.Transaction + bumpRolePermissionScopes + invalidatePermissionScopes + audit.Record
func (s *Service) RevokePermission(ctx context.Context, roleID, permissionID int64) error {
	role, err := s.roleByID(ctx, roleID)
	if err != nil {
		return err
	}
	scopes, err := s.permissionCacheScopesForRole(ctx, roleID)
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ? AND permission_id = ?", roleID, permissionID).Delete(&store.RolePermission{}).Error; err != nil {
			return err
		}
		return s.bumpRolePermissionScopes(ctx, tx, roleID)
	}); err != nil {
		return err
	}
	if err := s.invalidatePermissionScopes(ctx, scopes); err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    role.TenantID,
		Action:      auditActionRolePermissionRevoked,
		TargetType:  audit.TargetTypeRole,
		TargetID:    strconv.FormatInt(role.ID, 10),
		Metadata: map[string]any{
			"permission_id": permissionID,
		},
	})
}

// AssignRoles assigns roles to a member after verifying the roles belong to
// the same tenant as the member. Bumps permission versions and invalidates cache.
//
// Call chain: assignRoles → AssignRoles → memberByID + ensureRolesBelongToTenant + db.Transaction + bumpPermissionScopes + invalidatePermissionScopes + audit.Record
func (s *Service) AssignRoles(ctx context.Context, memberID int64, roleIDs []int64) error {
	member, err := s.memberByID(ctx, memberID)
	if err != nil {
		return err
	}
	if err := s.ensureRolesBelongToTenant(ctx, member.TenantID, roleIDs); err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, roleID := range roleIDs {
			record := store.MemberRole{
				MemberID: memberID,
				RoleID:   roleID,
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&record).Error; err != nil {
				return err
			}
		}
		return s.bumpPermissionScopes(ctx, tx, []permissionCacheScope{{UserID: member.UserID, TenantID: member.TenantID}})
	}); err != nil {
		return err
	}
	if err := s.invalidatePermissionScopes(ctx, []permissionCacheScope{{UserID: member.UserID, TenantID: member.TenantID}}); err != nil {
		return err
	}

	for _, roleID := range roleIDs {
		if err := s.audit.Record(ctx, audit.Entry{
			Action:     audit.ActionRoleAssigned,
			TargetType: audit.TargetTypeRole,
			TargetID:   strconv.FormatInt(roleID, 10),
			Metadata: map[string]any{
				"member_id": memberID,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

// memberByID fetches a tenant member by primary key.
func (s *Service) memberByID(ctx context.Context, memberID int64) (*store.TenantMember, error) {
	var member store.TenantMember
	if err := s.db.WithContext(ctx).First(&member, memberID).Error; err != nil {
		return nil, err
	}
	return &member, nil
}

// ensureActiveTenant returns an error if the tenant does not exist, is deleted, or is not active.
func (s *Service) ensureActiveTenant(ctx context.Context, tenantID int64) error {
	return s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, store.TenantStatusActive).
		First(&store.Tenant{}).Error
}

// ensureActiveUser returns an error if the user does not exist, is deleted, or is not active.
func (s *Service) ensureActiveUser(ctx context.Context, userID int64) error {
	return s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		First(&store.User{}).Error
}

// recordMembershipAdded writes a tenant_membership_added audit entry.
//
// Call chain: AddMember → recordMembershipAdded → audit.Record
func (s *Service) recordMembershipAdded(ctx context.Context, tenantID int64, member *store.TenantMember) error {
	return s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    tenantID,
		Action:      audit.ActionTenantMembershipAdded,
		TargetType:  audit.TargetTypeTenantMember,
		TargetID:    strconv.FormatInt(member.ID, 10),
		Metadata: map[string]any{
			"user_id": member.UserID,
		},
	})
}

// permissionCacheScopesForRole returns distinct (user, tenant) pairs for every
// member who holds the given role.
//
// Call chain: DeleteRole/GrantPermissions/RevokePermission → permissionCacheScopesForRole → db query
func (s *Service) permissionCacheScopesForRole(ctx context.Context, roleID int64) ([]permissionCacheScope, error) {
	var scopes []permissionCacheScope
	err := s.db.WithContext(ctx).
		Table("tenant_members").
		Select("DISTINCT tenant_members.user_id, tenant_members.tenant_id").
		Joins("JOIN member_roles ON member_roles.member_id = tenant_members.id").
		Where("member_roles.role_id = ? AND tenant_members.deleted_at IS NULL", roleID).
		Scan(&scopes).Error
	return scopes, err
}

// invalidatePermissionScopes invalidates the RBAC cache for each scope.
// No-op when the RBAC service is nil.
//
// Call chain: mutating service methods → invalidatePermissionScopes → rbac.InvalidateUserTenantPermissions
func (s *Service) invalidatePermissionScopes(ctx context.Context, scopes []permissionCacheScope) error {
	if s.rbac == nil {
		return nil
	}
	for _, scope := range scopes {
		if err := s.rbac.InvalidateUserTenantPermissions(ctx, scope.UserID, scope.TenantID); err != nil {
			return err
		}
	}
	return nil
}

// bumpPermissionScopes increments permission_version for the given (user, tenant)
// pairs to force cache misses.
//
// Call chain: RemoveMember/AssignRoles/RemoveRole → bumpPermissionScopes → db.Update
func (s *Service) bumpPermissionScopes(ctx context.Context, tx *gorm.DB, scopes []permissionCacheScope) error {
	seen := make(map[permissionCacheScope]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope.UserID == 0 || scope.TenantID == 0 {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		if err := tx.WithContext(ctx).
			Model(&store.TenantMember{}).
			Where("tenant_id = ? AND user_id = ? AND deleted_at IS NULL", scope.TenantID, scope.UserID).
			Update("permission_version", gorm.Expr("permission_version + 1")).Error; err != nil {
			return err
		}
	}
	return nil
}

// bumpTenantPermissionVersions increments permission_version for every active
// member in a tenant.
//
// Call chain: UpdateTenant/DeleteRole → bumpTenantPermissionVersions → db.Update
func (s *Service) bumpTenantPermissionVersions(ctx context.Context, tx *gorm.DB, tenantID int64) error {
	return tx.WithContext(ctx).
		Model(&store.TenantMember{}).
		Where("tenant_id = ? AND deleted_at IS NULL", tenantID).
		Update("permission_version", gorm.Expr("permission_version + 1")).Error
}

// bumpRolePermissionScopes increments permission_version for every member who
// holds the given role.
//
// Call chain: GrantPermissions/RevokePermission → bumpRolePermissionScopes → db.Update subquery
func (s *Service) bumpRolePermissionScopes(ctx context.Context, tx *gorm.DB, roleID int64) error {
	return tx.WithContext(ctx).
		Model(&store.TenantMember{}).
		Where("id IN (?)", tx.Model(&store.MemberRole{}).Select("member_id").Where("role_id = ?", roleID)).
		Where("deleted_at IS NULL").
		Update("permission_version", gorm.Expr("permission_version + 1")).Error
}

// roleByID fetches a role by primary key.
func (s *Service) roleByID(ctx context.Context, roleID int64) (*store.Role, error) {
	var role store.Role
	if err := s.db.WithContext(ctx).First(&role, roleID).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// ensureRolesBelongToTenant verifies every given role ID belongs to the specified tenant.
func (s *Service) ensureRolesBelongToTenant(ctx context.Context, tenantID int64, roleIDs []int64) error {
	if len(roleIDs) == 0 {
		return nil
	}

	uniqueRoleIDs := make([]int64, 0, len(roleIDs))
	seen := make(map[int64]struct{}, len(roleIDs))
	for _, roleID := range roleIDs {
		if _, ok := seen[roleID]; ok {
			continue
		}
		seen[roleID] = struct{}{}
		uniqueRoleIDs = append(uniqueRoleIDs, roleID)
	}

	var count int64
	if err := s.db.WithContext(ctx).
		Model(&store.Role{}).
		Where("tenant_id = ? AND id IN ?", tenantID, uniqueRoleIDs).
		Count(&count).Error; err != nil {
		return err
	}
	if count != int64(len(uniqueRoleIDs)) {
		return fmt.Errorf("roles must belong to the member tenant")
	}
	return nil
}

// RemoveRole un-assigns a role from a member, bumps permission versions, and
// invalidates the cache.
//
// Call chain: removeRole → RemoveRole → db.Transaction + bumpPermissionScopes + invalidatePermissionScopes + audit.Record
func (s *Service) RemoveRole(ctx context.Context, memberID, roleID int64) error {
	member, err := s.memberByID(ctx, memberID)
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("member_id = ? AND role_id = ?", memberID, roleID).Delete(&store.MemberRole{}).Error; err != nil {
			return err
		}
		return s.bumpPermissionScopes(ctx, tx, []permissionCacheScope{{UserID: member.UserID, TenantID: member.TenantID}})
	}); err != nil {
		return err
	}
	if err := s.invalidatePermissionScopes(ctx, []permissionCacheScope{{UserID: member.UserID, TenantID: member.TenantID}}); err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionRoleRemoved,
		TargetType: audit.TargetTypeRole,
		TargetID:   strconv.FormatInt(roleID, 10),
		Metadata: map[string]any{
			"member_id": memberID,
		},
	})
}
