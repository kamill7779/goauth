package session

import (
	"context"
	"errors"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

func (s *Service) Refresh(ctx context.Context, rawToken string) (*TokenPair, error) {
	var current store.RefreshToken
	if err := s.db.WithContext(ctx).Where("token_hash = ?", hashToken(rawToken)).First(&current).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	if current.RevokedAt != nil {
		return nil, s.rejectRefreshTokenReuse(ctx, current)
	}
	if current.ExpiresAt.Before(s.now()) {
		return nil, ErrInvalidRefreshToken
	}

	user, err := s.loadActiveUser(ctx, current.UserID)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}
	if user.TokenVersion != current.TokenVersion {
		return nil, ErrInvalidRefreshToken
	}
	if current.TenantID != 0 {
		if err := s.hasActiveMembership(ctx, current.UserID, current.TenantID); err != nil {
			return nil, ErrInvalidRefreshToken
		}
	}

	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		result := tx.Model(&store.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", current.ID).
			Update("revoked_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrRefreshTokenReuse
		}

		nextPair, err := s.issueTokenPairWithDB(ctx, tx, *user, current.TenantID, current.ClientID, current.SessionID, current.FamilyID)
		if err != nil {
			return err
		}

		var replacement store.RefreshToken
		if err := tx.Where("token_hash = ?", hashToken(nextPair.RefreshToken)).First(&replacement).Error; err != nil {
			return err
		}
		if err := tx.Model(&store.RefreshToken{}).
			Where("id = ?", current.ID).
			Update("replaced_by_token_id", replacement.ID).Error; err != nil {
			return err
		}

		pair = nextPair
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrRefreshTokenReuse) {
			return nil, s.rejectRefreshTokenReuse(ctx, current)
		}
		return nil, err
	}

	return pair, nil
}

func (s *Service) rejectRefreshTokenReuse(ctx context.Context, token store.RefreshToken) error {
	if err := s.revokeFamily(ctx, token.FamilyID); err != nil {
		return err
	}
	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: token.UserID,
		TenantID:    token.TenantID,
		Action:      audit.ActionRefreshTokenReuseDetected,
		TargetType:  audit.TargetTypeTokenFamily,
		TargetID:    token.FamilyID,
		Metadata: map[string]any{
			"session_id": token.SessionID,
			"client_id":  token.ClientID,
		},
	}); err != nil {
		return err
	}
	return ErrRefreshTokenReuse
}

func (s *Service) issueTokenPairWithDB(ctx context.Context, db *gorm.DB, user store.User, tenantID int64, clientID, sessionID, familyID string) (*TokenPair, error) {
	accessToken, err := s.signAccessToken(user, tenantID, clientID, sessionID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := randomID(32)
	if err != nil {
		return nil, err
	}

	record := store.RefreshToken{
		TokenHash:    hashToken(refreshToken),
		FamilyID:     familyID,
		SessionID:    sessionID,
		UserID:       user.ID,
		TenantID:     tenantID,
		TokenVersion: user.TokenVersion,
		ClientID:     clientID,
		ExpiresAt:    s.now().Add(s.refreshTokenTTL),
	}
	if err := db.WithContext(ctx).Create(&record).Error; err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    sessionID,
	}, nil
}

func (s *Service) Logout(ctx context.Context, sessionID string) error {
	var token store.RefreshToken
	if err := s.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("id ASC").
		First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}

	now := s.now()
	if err := s.db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", now).Error; err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		ActorUserID: token.UserID,
		TenantID:    token.TenantID,
		Action:      audit.ActionLogout,
		TargetType:  audit.TargetTypeSession,
		TargetID:    sessionID,
		Metadata: map[string]any{
			"client_id": token.ClientID,
		},
	})
}

func (s *Service) LogoutAll(ctx context.Context, userID int64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		if err := tx.Model(&store.RefreshToken{}).
			Where("user_id = ? AND revoked_at IS NULL", userID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}

		return tx.Model(&store.User{}).
			Where("id = ?", userID).
			Update("token_version", gorm.Expr("token_version + 1")).Error
	})
}

func (s *Service) revokeFamily(ctx context.Context, familyID string) error {
	now := s.now()
	return s.db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", now).Error
}
