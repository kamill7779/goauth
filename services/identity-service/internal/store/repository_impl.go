package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"goauth/services/identity-service/internal/identity"
)

// userRepo implements UserRepository backed by *gorm.DB.
type userRepo struct {
	db *gorm.DB
}

func (r *userRepo) FindByID(ctx context.Context, id int64) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, err
	}
	return &user, nil
}

func (r *userRepo) FindByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).Where("email = ?", identity.NormalizeEmail(email)).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepo) FindByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepo) Create(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *userRepo) Update(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *userRepo) BumpTokenVersion(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
}

func (r *userRepo) UpdatesByEmail(ctx context.Context, email string, updates map[string]any) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("email = ?", email).Updates(updates).Error
}

// ============================================================================
// Session / token repository implementation
// ============================================================================

// sessionRepo implements SessionRepository backed by *gorm.DB.
type sessionRepo struct {
	db *gorm.DB
}

func (r *sessionRepo) CreateLoginSession(ctx context.Context, session *LoginSession) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *sessionRepo) FindRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	var token RefreshToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *sessionRepo) RevokeRefreshToken(ctx context.Context, id int64, revokedAt time.Time) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).Where("id = ?", id).
		UpdateColumns(map[string]any{"revoked_at": &revokedAt}).Error
}

func (r *sessionRepo) RevokeTokenFamily(ctx context.Context, familyID string, revokedAt time.Time) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		UpdateColumns(map[string]any{"revoked_at": &revokedAt}).Error
}

func (r *sessionRepo) DeleteLoginSession(ctx context.Context, sessionID int64) error {
	return r.db.WithContext(ctx).Delete(&LoginSession{}, sessionID).Error
}

func (r *sessionRepo) FindLoginSessionByID(ctx context.Context, sessionID int64) (*LoginSession, error) {
	var session LoginSession
	if err := r.db.WithContext(ctx).First(&session, sessionID).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *sessionRepo) FindUserByID(ctx context.Context, userID int64) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *sessionRepo) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *sessionRepo) CreatePasswordHistory(ctx context.Context, entry *PasswordHistory) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

func (r *sessionRepo) Transaction(ctx context.Context, fn func(txRepo SessionRepository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&sessionRepo{db: tx})
	})
}

// NewUserRepository creates a GORM-backed UserRepository.
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepo{db: db}
}

// NewSessionRepository creates a GORM-backed SessionRepository.
func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepo{db: db}
}
