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

// FindByID returns a user by primary key, or gorm.ErrRecordNotFound.
//
// Call chain: any service → userRepo.FindByID → gorm.DB.First
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

// FindByEmail looks up a user by normalised email address.
//
// Call chain: any service → userRepo.FindByEmail → identity.NormalizeEmail / gorm.DB.First
func (r *userRepo) FindByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).Where("email = ?", identity.NormalizeEmail(email)).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByUsername looks up a user by exact username.
//
// Call chain: any service → userRepo.FindByUsername → gorm.DB.First
func (r *userRepo) FindByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// Create inserts a new user row.
func (r *userRepo) Create(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

// Update saves all fields of the user row.
func (r *userRepo) Update(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// BumpTokenVersion atomically increments token_version, invalidating all
// existing tokens for the user in O(1).
//
// Call chain: session/logout service → userRepo.BumpTokenVersion → gorm.DB.UpdateColumn
func (r *userRepo) BumpTokenVersion(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).
		UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error
}

// UpdatesByEmail applies a map of column updates to the user matching the given email.
//
// Call chain: auth service → userRepo.UpdatesByEmail → gorm.DB.Updates
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

// CreateLoginSession inserts a new login session row.
func (r *sessionRepo) CreateLoginSession(ctx context.Context, session *LoginSession) error {
	return r.db.WithContext(ctx).Create(session).Error
}

// FindRefreshTokenByHash looks up a refresh token by its SHA-256 hash.
//
// Call chain: session.Service → sessionRepo.FindRefreshTokenByHash → gorm.DB.First
func (r *sessionRepo) FindRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	var token RefreshToken
	if err := r.db.WithContext(ctx).Where("token_hash = ?", hash).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

// RevokeRefreshToken sets revoked_at on a single refresh token row.
//
// Call chain: session.Service → sessionRepo.RevokeRefreshToken → gorm.DB.UpdateColumns
func (r *sessionRepo) RevokeRefreshToken(ctx context.Context, id int64, revokedAt time.Time) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).Where("id = ?", id).
		UpdateColumns(map[string]any{"revoked_at": &revokedAt}).Error
}

// RevokeTokenFamily sets revoked_at on every non-revoked token in the family,
// implementing refresh-token rotation reuse detection (RFC 6749 §10.4).
//
// Call chain: session.Service → sessionRepo.RevokeTokenFamily → gorm.DB.UpdateColumns
func (r *sessionRepo) RevokeTokenFamily(ctx context.Context, familyID string, revokedAt time.Time) error {
	return r.db.WithContext(ctx).Model(&RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		UpdateColumns(map[string]any{"revoked_at": &revokedAt}).Error
}

// DeleteLoginSession hard-deletes a login session row by primary key.
func (r *sessionRepo) DeleteLoginSession(ctx context.Context, sessionID int64) error {
	return r.db.WithContext(ctx).Delete(&LoginSession{}, sessionID).Error
}

// FindLoginSessionByID returns a login session by primary key, or gorm.ErrRecordNotFound.
//
// Call chain: session.Service → sessionRepo.FindLoginSessionByID → gorm.DB.First
func (r *sessionRepo) FindLoginSessionByID(ctx context.Context, sessionID int64) (*LoginSession, error) {
	var session LoginSession
	if err := r.db.WithContext(ctx).First(&session, sessionID).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

// FindUserByID returns a user by primary key, or gorm.ErrRecordNotFound.
//
// Call chain: session.Service → sessionRepo.FindUserByID → gorm.DB.First
func (r *sessionRepo) FindUserByID(ctx context.Context, userID int64) (*User, error) {
	var user User
	if err := r.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateRefreshToken inserts a new refresh token row.
func (r *sessionRepo) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

// CreatePasswordHistory inserts a password history entry for reuse detection.
func (r *sessionRepo) CreatePasswordHistory(ctx context.Context, entry *PasswordHistory) error {
	return r.db.WithContext(ctx).Create(entry).Error
}

// Transaction executes fn inside a GORM database transaction, passing a
// transaction-scoped SessionRepository so the caller does not need to
// manage tx directly.
//
// Call chain: session.Service → sessionRepo.Transaction → gorm.DB.Transaction
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
