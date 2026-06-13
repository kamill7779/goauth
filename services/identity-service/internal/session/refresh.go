package session

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Refresh rotates a refresh token following RFC 6749 §10.4 with reuse detection.
// If a revoked token is presented (e.g., an attacker replays a stolen token after
// the legitimate client already rotated it), the entire token family is revoked.
// Refresh validates a refresh token, rotates it (old one revoked, new one
// issued), and returns a fresh token pair. Implements refresh token rotation
// to detect token reuse (RFC 6819 §5.2.2).
//
// Call chain: handler.refresh → service.Refresh → validateRefreshToken → IssueTokens
func (s *Service) Refresh(ctx context.Context, rawToken string) (*TokenPair, error) {
	token, err := s.sessions.FindRefreshTokenByHash(ctx, hashToken(rawToken))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	// Presenting an already-revoked token signals theft/replay: nuke the family.
	if token.RevokedAt != nil {
		return nil, s.rejectRefreshTokenReuse(ctx,  *token)
	}
	if token.ExpiresAt.Before(s.now()) {
		return nil, ErrInvalidRefreshToken
	}

	user, err := s.loadActiveUser(ctx, token.UserID)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}
	// TokenVersion mismatch means the user globally invalidated sessions (logout-all,
	// password change). Reject without family revocation since the token itself was valid.
	if user.TokenVersion != token.TokenVersion {
		return nil, ErrInvalidRefreshToken
	}
	if token.TenantID != 0 {
		if err := s.hasActiveMembership(ctx, token.UserID, token.TenantID); err != nil {
			return nil, ErrInvalidRefreshToken
		}
	}

	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		// SELECT FOR UPDATE on the login session serializes con *token refresh attempts
		// for the same session, so two simultaneous rotations cannot both succeed.
		if err := s.lockActiveSessionWithDB(ctx, tx, token.UserID, token.SessionID); err != nil {
			// If another transaction already rotated this token, treat as reuse.
			if s.wasRefreshTokenReplaced(ctx, tx, token.ID) {
				return ErrRefreshTokenReuse
			}
			return ErrInvalidRefreshToken
		}
		// Atomic revoke: RowsAffected != 1 means a racing rotation won — treat as reuse.
		result := tx.Model(&store.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", token.ID).
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

		nextPair, err := s.issueTokenPairWithDB(ctx, tx, *user, token.TenantID, token.ClientID, token.SessionID, token.FamilyID)
		if err != nil {
			return err
		}

		var replacement store.RefreshToken
		if err := tx.Where("token_hash = ?", hashToken(nextPair.RefreshToken)).First(&replacement).Error; err != nil {
			return err
		}
		if err := tx.Model(&store.RefreshToken{}).
			Where("id = ?", token.ID).
			Update("replaced_by_token_id", replacement.ID).Error; err != nil {
			return err
		}

		pair = nextPair
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrRefreshTokenReuse) {
			return nil, s.rejectRefreshTokenReuse(ctx,  *token)
		}
		return nil, err
	}

	return pair, nil
}

// rejectRefreshTokenReuse implements the RFC 6749 §10.4 mitigation: when a
// previously-rotated (revoked) refresh token is replayed, kill the entire token
// family AND the login session. This forces a re-login on every device sharing
// that family, defeating any attacker who captured the token.
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
	s.recordAuditBestEffort(ctx, audit.Entry{
		ActorUserID: token.UserID,
		TenantID:    token.TenantID,
		Action:      audit.ActionRefreshTokenReuseDetected,
		TargetType:  audit.TargetTypeTokenFamily,
		TargetID:    token.FamilyID,
		Metadata: map[string]any{
			"session_id": token.SessionID,
			"client_id":  token.ClientID,
		},
	})
	return ErrRefreshTokenReuse
}

// lockActiveSessionWithDB takes a SELECT FOR UPDATE on the login session to
// serialise concurrent refresh attempts for the same session.
//
// Call chain: Refresh → lockActiveSessionWithDB → DB SELECT FOR UPDATE
func (s *Service) lockActiveSessionWithDB(ctx context.Context, db *gorm.DB, userID int64, sessionID string) error {
	var loginSession store.LoginSession
	return db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", sessionID, userID).
		First(&loginSession).Error
}

// wasRefreshTokenReplaced checks whether a racing transaction already rotated
// this token (revoked_at IS NOT NULL AND replaced_by_token_id IS NOT NULL).
//
// Call chain: Refresh → wasRefreshTokenReplaced → DB query RefreshToken
func (s *Service) wasRefreshTokenReplaced(ctx context.Context, db *gorm.DB, tokenID int64) bool {
	var token store.RefreshToken
	err := db.WithContext(ctx).
		Select("revoked_at", "replaced_by_token_id").
		Where("id = ?", tokenID).
		First(&token).Error
	return err == nil && token.RevokedAt != nil && token.ReplacedByTokenID != nil
}

// issueTokenPairWithDB signs an access token and creates a refresh-token row in a
// single DB context, returning the raw tokens for the caller to hand to the client.
//
// Call chain: IssueTokens / Refresh / exchangeAuthorizationCode → issueTokenPairWithDB → signAccessToken + DB Create
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

// Logout revokes a single session by marking it as revoked in the repository
// and notifying the logout coordinator for back-channel propagation.
//
// Call chain: handler.logout → service.Logout → repo.RevokeSession + coordinator.Notify
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

	if s.logoutCoordinator != nil {
		_ = s.logoutCoordinator.NotifyClients(ctx, loginSession.UserID, sessionID)
	}

	s.recordAuditBestEffort(ctx, audit.Entry{
		ActorUserID: loginSession.UserID,
		TenantID:    loginSession.TenantID,
		Action:      audit.ActionLogout,
		TargetType:  audit.TargetTypeSession,
		TargetID:    sessionID,
		Metadata: map[string]any{
			"client_id": loginSession.ClientID,
		},
	})
	return nil
}

// LogoutAll revokes every active session for a user (used after password change
// or force-logout by admin).
//
// Call chain: handler.logoutAll / admin → service.LogoutAll → repo.RevokeAllSessions
func (s *Service) LogoutAll(ctx context.Context, userID int64) error {
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
	}); err != nil {
		return err
	}

	s.recordAuditBestEffort(ctx, audit.Entry{
		ActorUserID: userID,
		Action:      audit.ActionLogout,
		TargetType:  audit.TargetTypeUser,
		TargetID:    audit.UserTargetID(userID),
		Metadata: map[string]any{
			"scope": "all_sessions",
		},
	})
	return nil
}

// revokeFamily sets revoked_at on every non-revoked refresh token in the family.
func (s *Service) revokeFamily(ctx context.Context, familyID string) error {
	now := s.now()
	return s.db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", now).Error
}

// revokeLoginSession sets revoked_at on a single login session.
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

// revokeLoginSessionWithDB locks and revokes a login session within a transaction.
//
// Call chain: rejectRefreshTokenReuse → revokeLoginSessionWithDB → DB SELECT FOR UPDATE + UPDATE
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

// isSQLiteWriteLock detects SQLite "database table is locked" errors so callers
// can treat them as concurrency conflicts rather than hard failures.
func isSQLiteWriteLock(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "database table is locked") || strings.Contains(message, "database is locked")
}

// recordAuditBestEffort writes an audit entry and logs a warning on failure.
func (s *Service) recordAuditBestEffort(ctx context.Context, entry audit.Entry) {
	if err := s.audit.Record(ctx, entry); err != nil {
		slog.Warn("session audit record failed",
			"action", entry.Action,
			"target_type", entry.TargetType,
			"target_id", entry.TargetID,
			"error", err,
		)
	}
}
