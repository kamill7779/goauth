// Package store defines repository interfaces for data access, separating
// business logic from GORM implementation details.
package store

import (
	"context"
	"time"
)

// UserRepository abstracts user persistence.
type UserRepository interface {
	FindByID(ctx context.Context, id int64) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	Create(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error
	BumpTokenVersion(ctx context.Context, id int64) error
	UpdatesByEmail(ctx context.Context, email string, updates map[string]any) error
}

// SessionRepository abstracts token and session persistence.
type SessionRepository interface {
	CreateLoginSession(ctx context.Context, session *LoginSession) error
	FindRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id int64, revokedAt time.Time) error
	RevokeTokenFamily(ctx context.Context, familyID string, revokedAt time.Time) error
	DeleteLoginSession(ctx context.Context, sessionID int64) error
	FindLoginSessionByID(ctx context.Context, sessionID int64) (*LoginSession, error)
	FindUserByID(ctx context.Context, userID int64) (*User, error)
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	CreatePasswordHistory(ctx context.Context, entry *PasswordHistory) error
	Transaction(ctx context.Context, fn func(txRepo SessionRepository) error) error
}
