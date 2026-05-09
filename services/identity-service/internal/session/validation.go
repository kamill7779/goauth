package session

import (
	"context"
	"strconv"
	"strings"

	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

func (s *Service) loadActiveUser(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) hasActiveSession(ctx context.Context, userID int64, sessionID string) error {
	var token store.RefreshToken
	return s.db.WithContext(ctx).
		Where("session_id = ? AND user_id = ? AND revoked_at IS NULL", sessionID, userID).
		First(&token).Error
}

func (s *Service) hasActiveMembership(ctx context.Context, userID, tenantID int64) error {
	var member store.TenantMember
	return s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND status = ? AND deleted_at IS NULL", tenantID, userID, store.MemberStatusActive).
		First(&member).Error
}

func (s *Service) validateAccessClaims(ctx context.Context, claims accessClaims) error {
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return err
	}

	// JWT signature alone is not enough here: we also recheck live user, session,
	// and tenant state so logout, disable, or membership removal takes effect immediately.
	user, err := s.loadActiveUser(ctx, userID)
	if err != nil {
		return err
	}
	if user.TokenVersion != claims.TokenVersion {
		return gorm.ErrRecordNotFound
	}
	if claims.SessionID == "" {
		return gorm.ErrRecordNotFound
	}
	if err := s.hasActiveSession(ctx, userID, claims.SessionID); err != nil {
		return err
	}
	if claims.TenantID != 0 {
		if err := s.hasActiveMembership(ctx, userID, claims.TenantID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) isSystemUser(ctx context.Context, userID int64) (bool, error) {
	var user store.User
	if err := s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		First(&user).Error; err != nil {
		return false, err
	}
	if strings.EqualFold(user.Email, "root@example.com") {
		return true, nil
	}

	var count int64
	if err := s.db.WithContext(ctx).
		Table("roles").
		Joins("JOIN member_roles ON member_roles.role_id = roles.id").
		Joins("JOIN tenant_members ON tenant_members.id = member_roles.member_id").
		Where("tenant_members.status = ? AND tenant_members.deleted_at IS NULL", store.MemberStatusActive).
		Where("tenant_members.user_id = ?", userID).
		Where("roles.is_system = ? OR roles.code IN ?", true, []string{"root", "system-admin", "system_admin"}).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
