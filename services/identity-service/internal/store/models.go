package store

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
)

type User struct {
	ID              int64  `gorm:"primaryKey;autoIncrement"`
	Email           string `gorm:"size:255;not null;uniqueIndex"`
	EmailVerifiedAt *time.Time
	PasswordHash    string         `gorm:"size:255;not null"`
	DisplayName     string         `gorm:"size:255;not null"`
	AvatarURL       string         `gorm:"size:1024"`
	Status          string         `gorm:"size:32;not null;index"`
	TokenVersion    int            `gorm:"not null;default:0"`
	CreatedAt       time.Time      `gorm:"not null"`
	UpdatedAt       time.Time      `gorm:"not null"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

type UserIdentity struct {
	ID             int64     `gorm:"primaryKey;autoIncrement"`
	UserID         int64     `gorm:"not null;uniqueIndex:idx_user_provider"`
	Provider       string    `gorm:"size:64;not null;uniqueIndex:idx_provider_user;uniqueIndex:idx_user_provider"`
	ProviderUserID string    `gorm:"size:255;not null;uniqueIndex:idx_provider_user"`
	Email          string    `gorm:"size:255"`
	EmailVerified  bool      `gorm:"not null;default:false"`
	Username       string    `gorm:"size:255"`
	DisplayName    string    `gorm:"size:255"`
	AvatarURL      string    `gorm:"size:1024"`
	CreatedAt      time.Time `gorm:"not null"`
	UpdatedAt      time.Time `gorm:"not null"`
}

type Tenant struct {
	ID        int64          `gorm:"primaryKey;autoIncrement"`
	Name      string         `gorm:"size:255;not null"`
	Slug      string         `gorm:"size:255;not null;uniqueIndex"`
	Status    string         `gorm:"size:32;not null;index"`
	CreatedAt time.Time      `gorm:"not null"`
	UpdatedAt time.Time      `gorm:"not null"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type TenantMember struct {
	ID        int64          `gorm:"primaryKey;autoIncrement"`
	TenantID  int64          `gorm:"not null;index;uniqueIndex:idx_tenant_member"`
	UserID    int64          `gorm:"not null;index;uniqueIndex:idx_tenant_member"`
	Status    string         `gorm:"size:32;not null;index"`
	CreatedAt time.Time      `gorm:"not null"`
	UpdatedAt time.Time      `gorm:"not null"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

type Role struct {
	ID          int64     `gorm:"primaryKey;autoIncrement"`
	TenantID    int64     `gorm:"not null;index;uniqueIndex:idx_role_tenant_code"`
	Name        string    `gorm:"size:255;not null"`
	Code        string    `gorm:"size:128;not null;uniqueIndex:idx_role_tenant_code"`
	Description string    `gorm:"size:1024"`
	IsSystem    bool      `gorm:"not null;default:false"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time `gorm:"not null"`
}

type Permission struct {
	ID          int64     `gorm:"primaryKey;autoIncrement"`
	Resource    string    `gorm:"size:128;not null"`
	Action      string    `gorm:"size:128;not null"`
	Code        string    `gorm:"size:255;not null;uniqueIndex"`
	Description string    `gorm:"size:1024"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time `gorm:"not null"`
}

type RolePermission struct {
	RoleID       int64 `gorm:"primaryKey"`
	PermissionID int64 `gorm:"primaryKey"`
}

type MemberRole struct {
	MemberID int64 `gorm:"primaryKey"`
	RoleID   int64 `gorm:"primaryKey"`
}

type OAuthClient struct {
	ID                      int64          `gorm:"primaryKey;autoIncrement"`
	TenantID                int64          `gorm:"not null;index"`
	ClientID                string         `gorm:"size:255;not null;uniqueIndex"`
	ClientSecretHash        string         `gorm:"size:255;not null"`
	Name                    string         `gorm:"size:255;not null"`
	RedirectURIs            datatypes.JSON `gorm:"not null"`
	AllowedScopes           datatypes.JSON `gorm:"not null"`
	GrantTypes              datatypes.JSON `gorm:"not null"`
	TokenEndpointAuthMethod string         `gorm:"size:64;not null"`
	Status                  string         `gorm:"size:32;not null;index"`
	CreatedAt               time.Time      `gorm:"not null"`
	UpdatedAt               time.Time      `gorm:"not null"`
}

type OAuthAuthorizationCode struct {
	ID                  int64     `gorm:"primaryKey;autoIncrement"`
	CodeHash            string    `gorm:"size:255;not null;uniqueIndex"`
	ClientID            string    `gorm:"size:255;not null;index"`
	UserID              int64     `gorm:"not null;index"`
	TenantID            int64     `gorm:"not null;index"`
	RedirectURI         string    `gorm:"size:1024;not null"`
	Scope               string    `gorm:"size:1024"`
	CodeChallenge       string    `gorm:"size:255"`
	CodeChallengeMethod string    `gorm:"size:32"`
	Nonce               string    `gorm:"size:255"`
	ExpiresAt           time.Time `gorm:"not null;index"`
	ConsumedAt          *time.Time
	CreatedAt           time.Time `gorm:"not null"`
}

type RefreshToken struct {
	ID                int64      `gorm:"primaryKey;autoIncrement"`
	TokenHash         string     `gorm:"size:255;not null;uniqueIndex"`
	FamilyID          string     `gorm:"size:255;not null;index"`
	SessionID         string     `gorm:"size:255;not null;index"`
	UserID            int64      `gorm:"not null;index"`
	TenantID          int64      `gorm:"not null;index"`
	ClientID          string     `gorm:"size:255;index"`
	UserAgent         string     `gorm:"size:1024"`
	IPAddress         string     `gorm:"size:255"`
	ExpiresAt         time.Time  `gorm:"not null;index"`
	RevokedAt         *time.Time `gorm:"index"`
	ReplacedByTokenID *int64
	CreatedAt         time.Time `gorm:"not null"`
}

type ExternalProviderConfig struct {
	ID                     int64          `gorm:"primaryKey;autoIncrement"`
	Provider               string         `gorm:"size:64;not null;index"`
	Name                   string         `gorm:"size:255;not null"`
	ClientID               string         `gorm:"size:255;not null"`
	ClientSecretCiphertext string         `gorm:"size:2048;not null"`
	Scopes                 datatypes.JSON `gorm:"not null"`
	Enabled                bool           `gorm:"not null;default:false"`
	CreatedAt              time.Time      `gorm:"not null"`
	UpdatedAt              time.Time      `gorm:"not null"`
}

type AuditLog struct {
	ID          int64          `gorm:"primaryKey;autoIncrement"`
	ActorUserID int64          `gorm:"index"`
	TenantID    int64          `gorm:"index"`
	Action      string         `gorm:"size:255;not null;index"`
	TargetType  string         `gorm:"size:255;not null"`
	TargetID    string         `gorm:"size:255;not null"`
	IPAddress   string         `gorm:"size:255"`
	UserAgent   string         `gorm:"size:1024"`
	Metadata    datatypes.JSON `gorm:"not null"`
	CreatedAt   time.Time      `gorm:"not null"`
}
