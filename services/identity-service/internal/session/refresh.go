package session

import (
	"context"
	"errors"
	"strings"
	"time"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
		if err := s.lockActiveSessionWithDB(ctx, tx, current.UserID, current.SessionID); err != nil {
			return ErrInvalidRefreshToken
		}
		result := tx.Model(&store.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", current.ID).
			Update("revoked_at", now)
		if result.Error != nil {
			if isSQLiteWriteLock(result.Error) {
				return ErrRefreshTokenReuse
			}
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
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		if token.SessionID != "" {
			if err := tx.Model(&store.LoginSession{}).
				Where("id = ? AND revoked_at IS NULL", token.SessionID).
				Update("revoked_at", now).Error; err != nil {
				if isSQLiteWriteLock(err) {
					return ErrRefreshTokenReuse
				}
				return err
			}
		}
		if err := tx.Model(&store.RefreshToken{}).
			Where("family_id = ? AND revoked_at IS NULL", token.FamilyID).
			Update("revoked_at", now).Error; err != nil {
			if isSQLiteWriteLock(err) {
				return ErrRefreshTokenReuse
			}
			return err
		}
		return nil
	})
	if err != nil {
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

func (s *Service) lockActiveSessionWithDB(ctx context.Context, db *gorm.DB, userID int64, sessionID string) error {
	var loginSession store.LoginSession
	return db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", sessionID, userID).
		First(&loginSession).Error
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
	var loginSession store.LoginSession
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", sessionID).
			First(&loginSession).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}

		now := s.now()
		if err := tx.Model(&store.LoginSession{}).
			Where("id = ? AND revoked_at IS NULL", sessionID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}
		return tx.Model(&store.RefreshToken{}).
			Where("session_id = ? AND revoked_at IS NULL", sessionID).
			Update("revoked_at", now).Error
	}); err != nil {
		return err
	}
	if loginSession.ID == "" {
		return nil
	}

	return s.audit.Record(ctx, audit.Entry{
		ActorUserID: loginSession.UserID,
		TenantID:    loginSession.TenantID,
		Action:      audit.ActionLogout,
		TargetType:  audit.TargetTypeSession,
		TargetID:    sessionID,
		Metadata: map[string]any{
			"client_id": loginSession.ClientID,
		},
	})
}

func (s *Service) LogoutAll(ctx context.Context, userID int64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		if err := tx.Model(&store.LoginSession{}).
			Where("user_id = ? AND revoked_at IS NULL", userID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}
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

func (s *Service) revokeLoginSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	now := s.now()
	return s.db.WithContext(ctx).
		Model(&store.LoginSession{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", now).Error
}

func (s *Service) revokeLoginSessionWithDB(ctx context.Context, db *gorm.DB, sessionID string, now time.Time) error {
	if err := db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", sessionID).
		First(&store.LoginSession{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	return db.Model(&store.LoginSession{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", now).Error
}

func isSQLiteWriteLock(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "database table is locked") || strings.Contains(message, "database is locked")
}
