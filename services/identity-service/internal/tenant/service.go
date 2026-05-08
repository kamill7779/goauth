package tenant

import (
	"context"
	"strconv"

	"example.com/identity-service/internal/audit"
	"example.com/identity-service/internal/rbac"
	"example.com/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Service struct {
	db    *gorm.DB
	rbac  *rbac.Service
	audit audit.Recorder
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

func NewService(db *gorm.DB, rbacService *rbac.Service) *Service {
	return &Service{
		db:    db,
		rbac:  rbacService,
		audit: audit.NoopRecorder{},
	}
}

func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

func (s *Service) DB() *gorm.DB {
	return s.db
}

func (s *Service) ListTenants(ctx context.Context) ([]store.Tenant, error) {
	var tenants []store.Tenant
	err := s.db.WithContext(ctx).Order("id ASC").Find(&tenants).Error
	return tenants, err
}

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
	return record, nil
}

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
		if err := s.db.WithContext(ctx).Model(&store.Tenant{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return nil, err
		}
	}

	var record store.Tenant
	if err := s.db.WithContext(ctx).First(&record, id).Error; err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *Service) AddMember(ctx context.Context, input AddMemberInput) (*store.TenantMember, error) {
	status := input.Status
	if status == "" {
		status = store.MemberStatusActive
	}

	member := &store.TenantMember{
		TenantID: input.TenantID,
		UserID:   input.UserID,
		Status:   status,
	}
	if err := s.db.WithContext(ctx).Create(member).Error; err != nil {
		return nil, err
	}
	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: 0,
		TenantID:    input.TenantID,
		Action:      audit.ActionTenantMembershipAdded,
		TargetType:  audit.TargetTypeTenantMember,
		TargetID:    strconv.FormatInt(member.ID, 10),
		Metadata: map[string]any{
			"user_id": member.UserID,
		},
	}); err != nil {
		return nil, err
	}
	return member, nil
}

func (s *Service) RemoveMember(ctx context.Context, tenantID, userID int64) error {
	var members []store.TenantMember
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Find(&members).Error; err != nil {
		return err
	}

	for _, member := range members {
		if s.rbac != nil {
			if err := s.rbac.InvalidateMemberPermissions(ctx, member.ID); err != nil {
				return err
			}
		}
		if err := s.db.WithContext(ctx).Where("member_id = ?", member.ID).Delete(&store.MemberRole{}).Error; err != nil {
			return err
		}
	}

	if err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&store.TenantMember{}).Error; err != nil {
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

func (s *Service) ListRoles(ctx context.Context, tenantID int64) ([]store.Role, error) {
	var roles []store.Role
	query := s.db.WithContext(ctx).Order("id ASC")
	if tenantID != 0 {
		query = query.Where("tenant_id = ?", tenantID)
	}
	err := query.Find(&roles).Error
	return roles, err
}

func (s *Service) CreateRole(ctx context.Context, input CreateRoleInput) (*store.Role, error) {
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
	return role, nil
}

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
	return &role, nil
}

func (s *Service) DeleteRole(ctx context.Context, id int64) error {
	if s.rbac != nil {
		if err := s.rbac.InvalidateRolePermissions(ctx, id); err != nil {
			return err
		}
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", id).Delete(&store.RolePermission{}).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", id).Delete(&store.MemberRole{}).Error; err != nil {
			return err
		}
		return tx.Delete(&store.Role{}, id).Error
	})
}

func (s *Service) GrantPermissions(ctx context.Context, roleID int64, permissionIDs []int64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, permissionID := range permissionIDs {
			record := store.RolePermission{
				RoleID:       roleID,
				PermissionID: permissionID,
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&record).Error; err != nil {
				return err
			}
		}
		if s.rbac != nil {
			return s.rbac.InvalidateRolePermissions(ctx, roleID)
		}
		return nil
	})
}

func (s *Service) RevokePermission(ctx context.Context, roleID, permissionID int64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if s.rbac != nil {
			if err := s.rbac.InvalidateRolePermissions(ctx, roleID); err != nil {
				return err
			}
		}
		return tx.Where("role_id = ? AND permission_id = ?", roleID, permissionID).Delete(&store.RolePermission{}).Error
	})
}

func (s *Service) AssignRoles(ctx context.Context, memberID int64, roleIDs []int64) error {
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
		if s.rbac != nil {
			if err := s.rbac.InvalidateMemberPermissions(ctx, memberID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
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

func (s *Service) RemoveRole(ctx context.Context, memberID, roleID int64) error {
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if s.rbac != nil {
			if err := s.rbac.InvalidateMemberPermissions(ctx, memberID); err != nil {
				return err
			}
		}
		if err := tx.Where("member_id = ? AND role_id = ?", memberID, roleID).Delete(&store.MemberRole{}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
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
