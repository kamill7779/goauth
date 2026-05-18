// Package audit provides structured audit logging for security-relevant events.
// All mutations (login, logout, password change, role assignment, etc.) are
// recorded with actor, target, and metadata for compliance and forensics.
package audit

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	ActionLogin                     = "login"
	ActionLogout                    = "logout"
	ActionPasswordChanged           = "password_changed"
	ActionPasswordReset             = "password_reset"
	ActionRefreshTokenReuseDetected = "refresh_reuse_detected"
	ActionTenantMembershipAdded     = "tenant_membership_added"
	ActionTenantMembershipRemoved   = "tenant_membership_removed"
	ActionRoleAssigned              = "role_assigned"
	ActionRoleRemoved               = "role_removed"
	ActionOAuthClientChanged        = "oauth_client_changed"
	ActionExternalIdentityChanged   = "external_identity_binding_changed"
	ActionUserCreated               = "user_created"
	ActionUserUpdated               = "user_updated"
	ActionUserDisabled              = "user_disabled"
	ActionUserEnabled               = "user_enabled"
)

const (
	TargetTypeUser         = "user"
	TargetTypeTenantMember = "tenant_member"
	TargetTypeRole         = "role"
	TargetTypeSession      = "session"
	TargetTypeTokenFamily  = "refresh_token_family"
	TargetTypeOAuthClient  = "oauth_client"
	TargetTypeIdentity     = "external_identity"
)

type Entry struct {
	ActorUserID int64
	TenantID    int64
	Action      string
	TargetType  string
	TargetID    string
	IPAddress   string
	UserAgent   string
	Metadata    map[string]any
}

type Recorder interface {
	Record(ctx context.Context, entry Entry) error
}

type NoopRecorder struct{}

func (NoopRecorder) Record(context.Context, Entry) error {
	return nil
}

type Service struct {
	db  *gorm.DB
	now func() time.Time
}

func NewService(db *gorm.DB) *Service {
	return &Service{
		db:  db,
		now: time.Now,
	}
}

func (s *Service) Record(ctx context.Context, entry Entry) error {
	if entry.Metadata == nil {
		entry.Metadata = map[string]any{}
	}
	payload, err := json.Marshal(entry.Metadata)
	if err != nil {
		return err
	}

	targetID := entry.TargetID
	if targetID == "" {
		targetID = "unknown"
	}

	record := store.AuditLog{
		ActorUserID: entry.ActorUserID,
		TenantID:    entry.TenantID,
		Action:      entry.Action,
		TargetType:  entry.TargetType,
		TargetID:    targetID,
		IPAddress:   entry.IPAddress,
		UserAgent:   entry.UserAgent,
		Metadata:    datatypes.JSON(payload),
		CreatedAt:   s.now(),
	}

	return s.db.WithContext(ctx).Create(&record).Error
}

func UserTargetID(userID int64) string {
	return strconv.FormatInt(userID, 10)
}
