package session

import (
	"context"
	"strconv"

	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

// systemRoleCodes is a fallback for legacy role records lacking is_system=true.
// Both kebab and snake variants are kept because historical seed data used either.
var systemRoleCodes = []string{"root", "system-admin", "system_admin"}

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
		Joins("JOIN login_sessions ON login_sessions.id = refresh_tokens.session_id").
		Where("refresh_tokens.session_id = ? AND refresh_tokens.user_id = ? AND refresh_tokens.revoked_at IS NULL", sessionID, userID).
		Where("login_sessions.revoked_at IS NULL").
		First(&token).Error
}

func (s *Service) hasActiveMembership(ctx context.Context, userID, tenantID int64) error {
	var tenant store.Tenant
	if err := s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, store.TenantStatusActive).
		First(&tenant).Error; err != nil {
		return err
	}

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
	if claims.TokenUse != accessTokenUseSession {
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
	if _, err := s.loadActiveUser(ctx, userID); err != nil {
		return false, err
	}
	var count int64
	if err := s.db.WithContext(ctx).
		Table("tenant_members AS tm").
		Joins("JOIN tenants AS t ON t.id = tm.tenant_id AND t.status = ? AND t.deleted_at IS NULL", store.TenantStatusActive).
		Joins("JOIN member_roles AS mr ON mr.member_id = tm.id").
		Joins("JOIN roles AS r ON r.id = mr.role_id AND r.tenant_id = tm.tenant_id").
		Where("tm.user_id = ? AND tm.status = ? AND tm.deleted_at IS NULL", userID, store.MemberStatusActive).
		Where("r.is_system = ? OR r.code IN ?", true, systemRoleCodes).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
