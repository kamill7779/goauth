package invite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/mailer"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

const (
	inviteTTL     = 72 * time.Hour
	inviteIssuer  = "goauth"
	inviteSubject = "invite"
)

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteExpired  = errors.New("invite has expired")
	ErrInviteRedeemed = errors.New("invite has already been redeemed")
	ErrInviteRevoked  = errors.New("invite has been revoked")
	ErrInvalidToken   = errors.New("invalid invite token")
)

// inviteClaims are the JWT claims embedded in an invite token.
type inviteClaims struct {
	jwt.RegisteredClaims
	TenantID int64  `json:"tid"`
	RoleID   int64  `json:"rid"`
	Email    string `json:"email"`
}

// Service manages tenant member invitations.
type Service struct {
	db         *gorm.DB
	privateKey *rsa.PrivateKey
	mailer     mailer.Sender
	tmpl       *mailer.TemplateEngine
	audit      audit.Recorder
	appName    string
	baseURL    string
}

// NewService creates an invite Service.
func NewService(db *gorm.DB, privateKey *rsa.PrivateKey, mailSender mailer.Sender, tmpl *mailer.TemplateEngine, appName, baseURL string) *Service {
	if mailSender == nil {
		mailSender = mailer.NoopSender{}
	}
	if tmpl == nil {
		tmpl = mailer.NewTemplateEngine("en")
	}
	return &Service{
		db:         db,
		privateKey: privateKey,
		mailer:     mailSender,
		tmpl:       tmpl,
		audit:      audit.NoopRecorder{},
		appName:    appName,
		baseURL:    baseURL,
	}
}

func (s *Service) SetAuditRecorder(r audit.Recorder) {
	if r == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = r
}

// CreateInput holds the parameters for creating an invite.
type CreateInput struct {
	TenantID    int64
	RoleID      int64
	TargetEmail string
	InviterID   int64
}

// Create generates a signed invite token, stores the invite record, and sends the email.
func (s *Service) Create(ctx context.Context, input CreateInput) (*store.Invite, error) {
	if input.TenantID == 0 || input.RoleID == 0 || input.TargetEmail == "" {
		return nil, fmt.Errorf("tenant_id, role_id, and target_email are required")
	}

	expiresAt := time.Now().Add(inviteTTL)
	jti, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}

	claims := inviteClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    inviteIssuer,
			Subject:   inviteSubject,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
		TenantID: input.TenantID,
		RoleID:   input.RoleID,
		Email:    input.TargetEmail,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign invite token: %w", err)
	}

	tokenHash := hashToken(signed)

	invite := &store.Invite{
		TokenHash:     tokenHash,
		TenantID:      input.TenantID,
		RoleID:        input.RoleID,
		InviterUserID: input.InviterID,
		TargetEmail:   input.TargetEmail,
		Status:        store.InviteStatusPending,
		ExpiresAt:     expiresAt,
		CreatedAt:     time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(invite).Error; err != nil {
		return nil, fmt.Errorf("store invite: %w", err)
	}

	// Send invite email.
	inviteLink := fmt.Sprintf("%s/invite?token=%s", s.baseURL, signed)
	subject, body, _ := s.tmpl.Render("tenant_invite", "en", mailer.TemplateData{
		AppName:   s.appName,
		UserName:  input.TargetEmail,
		Link:      inviteLink,
		ExpiryMin: int(inviteTTL.Minutes()),
	})
	_ = s.mailer.Send(ctx, mailer.Message{
		To:      input.TargetEmail,
		Subject: subject,
		Body:    body,
	})

	_ = s.audit.Record(ctx, audit.Entry{
		ActorUserID: input.InviterID,
		TenantID:    input.TenantID,
		Action:      "invite_created",
		TargetType:  "invite",
		TargetID:    fmt.Sprintf("%d", invite.ID),
		Metadata: map[string]any{
			"target_email": input.TargetEmail,
			"role_id":      input.RoleID,
		},
	})

	return invite, nil
}

// RedeemInput holds the parameters for redeeming an invite.
type RedeemInput struct {
	Token  string
	UserID int64
}

// Redeem validates the invite token and adds the user to the tenant with the assigned role.
func (s *Service) Redeem(ctx context.Context, input RedeemInput) error {
	if input.Token == "" {
		return ErrInvalidToken
	}

	// Parse and verify JWT.
	var claims inviteClaims
	_, err := jwt.ParseWithClaims(input.Token, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &s.privateKey.PublicKey, nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.Subject != inviteSubject {
		return ErrInvalidToken
	}

	tokenHash := hashToken(input.Token)

	// Load invite record.
	var invite store.Invite
	if err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).First(&invite).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInviteNotFound
		}
		return err
	}

	switch invite.Status {
	case store.InviteStatusRedeemed:
		return ErrInviteRedeemed
	case store.InviteStatusRevoked:
		return ErrInviteRevoked
	}
	if time.Now().After(invite.ExpiresAt) {
		return ErrInviteExpired
	}

	// Add user to tenant with the assigned role in a transaction.
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Upsert tenant member.
		var member store.TenantMember
		err := tx.Where("tenant_id = ? AND user_id = ?", invite.TenantID, input.UserID).First(&member).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			member = store.TenantMember{
				TenantID:  invite.TenantID,
				UserID:    input.UserID,
				Status:    store.MemberStatusActive,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			if err := tx.Create(&member).Error; err != nil {
				return fmt.Errorf("create tenant member: %w", err)
			}
		} else if err != nil {
			return err
		}

		// Assign role.
		memberRole := store.MemberRole{
			MemberID: member.ID,
			RoleID:   invite.RoleID,
		}
		if err := tx.Where(memberRole).FirstOrCreate(&memberRole).Error; err != nil {
			return fmt.Errorf("assign role: %w", err)
		}

		// Mark invite as redeemed.
		now := time.Now()
		return tx.Model(&invite).Updates(map[string]any{
			"status":              store.InviteStatusRedeemed,
			"redeemed_at":         now,
			"redeemed_by_user_id": input.UserID,
		}).Error
	}); err != nil {
		return err
	}

	_ = s.audit.Record(ctx, audit.Entry{
		ActorUserID: input.UserID,
		TenantID:    invite.TenantID,
		Action:      "invite_redeemed",
		TargetType:  "invite",
		TargetID:    fmt.Sprintf("%d", invite.ID),
		Metadata: map[string]any{
			"role_id": invite.RoleID,
		},
	})

	return nil
}

// List returns paginated invites for a tenant.
func (s *Service) List(ctx context.Context, tenantID int64, page, pageSize int) ([]store.Invite, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	var total int64
	query := s.db.WithContext(ctx).Model(&store.Invite{}).Where("tenant_id = ?", tenantID)
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var invites []store.Invite
	if err := query.Order("created_at DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&invites).Error; err != nil {
		return nil, 0, err
	}
	return invites, total, nil
}

// Revoke marks an invite as revoked.
func (s *Service) Revoke(ctx context.Context, inviteID int64) error {
	result := s.db.WithContext(ctx).Model(&store.Invite{}).
		Where("id = ? AND status = ?", inviteID, store.InviteStatusPending).
		Update("status", store.InviteStatusRevoked)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrInviteNotFound
	}
	return nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
