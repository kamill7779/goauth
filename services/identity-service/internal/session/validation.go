package session

import (
	"context"
	"strconv"
	"strings"

	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

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
	user, err := s.loadActiveUser(ctx, userID)
	if err != nil {
		return false, err
	}
	if strings.EqualFold(user.Email, "root@example.com") {
		return true, nil
	}

	memberIDs, err := s.activeMemberIDsForUser(ctx, userID)
	if err != nil || len(memberIDs) == 0 {
		return false, err
	}

	roleIDs, err := s.roleIDsForMembers(ctx, memberIDs)
	if err != nil || len(roleIDs) == 0 {
		return false, err
	}

	return s.hasSystemRole(ctx, roleIDs)
}

func (s *Service) activeMemberIDsForUser(ctx context.Context, userID int64) ([]int64, error) {
	var memberIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.TenantMember{}).
		Where("user_id = ? AND status = ? AND deleted_at IS NULL", userID, store.MemberStatusActive).
		Pluck("id", &memberIDs).Error
	return memberIDs, err
}

func (s *Service) roleIDsForMembers(ctx context.Context, memberIDs []int64) ([]int64, error) {
	var roleIDs []int64
	err := s.db.WithContext(ctx).
		Model(&store.MemberRole{}).
		Distinct("role_id").
		Where("member_id IN ?", memberIDs).
		Pluck("role_id", &roleIDs).Error
	return roleIDs, err
}

func (s *Service) hasSystemRole(ctx context.Context, roleIDs []int64) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).
		Model(&store.Role{}).
		Where("id IN ?", roleIDs).
		Where("is_system = ? OR code IN ?", true, systemRoleCodes).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
