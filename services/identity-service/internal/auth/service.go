// Package auth implements self-service authentication flows.
//
// Call chain (inbound HTTP → service → persistence):
//
//	handler.go          service.go            store
//	──────────          ──────────            ─────
//	sendCode      ──→  SendEmailCode  ──→  Redis (email_code:{purpose}:{email})
//	register      ──→  Register       ──→  UserRepository.Create + policy.Apply
//	login         ──→  Login          ──→  UserRepository.FindBy* + lockout + audit
//	forgotPassword──→  ForgotPassword ──→  SendEmailCode(password_forgot)
//	resetPassword ──→  ResetPassword  ──→  requireEmailCode + UpdatePassword
//
// Dependencies are injected via Dependencies struct at construction time.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/identity"
	"goauth/services/identity-service/internal/lockout"
	"goauth/services/identity-service/internal/mailer"
	"goauth/services/identity-service/internal/password"
	"goauth/services/identity-service/internal/provisioning"
	"goauth/services/identity-service/internal/store"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var (
	ErrInvalidEmailCode    = errors.New("invalid email code")
	ErrEmailAlreadyUsed    = errors.New("email already exists")
	ErrUsernameAlreadyUsed = errors.New("username already exists")
	ErrInvalidUsername     = errors.New("invalid username")
	ErrInvalidCredential   = errors.New("invalid credentials")
	ErrUserDisabled        = errors.New("user disabled")
	ErrAccountLocked       = errors.New("account locked")
)

type MailMessage = mailer.Message
type MailSender = mailer.Sender

type RegisterInput struct {
	Username    string
	Nickname    string
	Email       string
	DisplayName string
	Password    string
	EmailCode   string
	CodePurpose string
}

type LoginInput struct {
	Identifier string
	Email      string // legacy fallback
	Password   string
}

type ResetPasswordInput struct {
	Email       string
	NewPassword string
	EmailCode   string
}

type Service struct {
	users    store.UserRepository
	redis    *redis.Client
	mailer   MailSender
	audit    audit.Recorder
	policy   *provisioning.DefaultMembershipPolicy
	lockout  *lockout.Manager
	pwPolicy password.Policy
	now      func() time.Time
	db       *gorm.DB // retained for transaction orchestration until provisioning is migrated
}

// Dependencies bundles required collaborators for auth.Service.
// All optional fields default to safe noop values when nil/zero.
type Dependencies struct {
	Users    store.UserRepository
	Redis    *redis.Client
	Mailer   MailSender
	DB       *gorm.DB // retained for transactional orchestration during migration
	Audit    audit.Recorder
	Policy   *provisioning.DefaultMembershipPolicy
	Lockout  *lockout.Manager
	Password password.Policy
}

// Deprecated: NewService is the legacy constructor. Use NewService(deps Dependencies) for new code.
// Kept for migration: external packages may still use the old 4-arg signature temporarily.
func NewService(users store.UserRepository, redisClient *redis.Client, mailSender MailSender, db *gorm.DB) *Service {
	return NewServiceWithDeps(Dependencies{
		Users:  users,
		Redis:  redisClient,
		Mailer: mailSender,
		DB:     db,
	})
}

// NewServiceWithDeps creates a fully-wired auth.Service.
func NewServiceWithDeps(deps Dependencies) *Service {
	if deps.Mailer == nil {
		deps.Mailer = mailer.NoopSender{}
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopRecorder{}
	}

	return &Service{
		users:    deps.Users,
		db:       deps.DB,
		redis:    deps.Redis,
		mailer:   deps.Mailer,
		audit:    deps.Audit,
		policy:   deps.Policy,
		lockout:  deps.Lockout,
		pwPolicy: deps.Password,
		now:      time.Now,
	}
}

// DB exposes the underlying *gorm.DB for migration-compatible access.
func (s *Service) DB() *gorm.DB { return s.db }

// SendEmailCode generates a 6-digit code, stores it in Redis with a TTL,
// and dispatches it via the configured mailer. Returns the code for test
// convenience; callers must not expose it beyond the mailer.
//
// Call chain: handler.sendCode / handler.forgotPassword → SendEmailCode → Redis SET + mailer.Send
func (s *Service) SendEmailCode(ctx context.Context, purpose, email string) (string, error) {
	purpose, err := normalizeEmailCodePurpose(purpose)
	if err != nil {
		return "", err
	}

	code, err := generateEmailCode()
	if err != nil {
		return "", fmt.Errorf("generate email code: %w", err)
	}
	if err := storeEmailCode(ctx, s.redis, purpose, identity.NormalizeEmail(email), code); err != nil {
		return "", fmt.Errorf("store email code: %w", err)
	}
	if err := s.mailer.Send(ctx, MailMessage{
		To:      identity.NormalizeEmail(email),
		Subject: "GoAuth verification code",
		Body:    code,
	}); err != nil {
		return "", fmt.Errorf("send email code: %w", err)
	}
	return code, nil
}

// Register creates a new user after verifying the email code. It normalises
// the email, derives a username when none is given, hashes the password with
// bcrypt, persists via UserRepository, and applies the default membership
// policy. Returns the created user on success.
//
// Call chain: handler.register → service.Register → repo.Create + policy.Apply
func (s *Service) Register(ctx context.Context, input RegisterInput) (*store.User, error) {
	purpose, err := normalizeEmailCodePurpose(input.CodePurpose)
	if err != nil {
		return nil, err
	}

	email := identity.NormalizeEmail(input.Email)
	if err := s.requireEmailCode(ctx, purpose, email, input.EmailCode); err != nil {
		return nil, err
	}

	username := strings.TrimSpace(input.Username)
	if username == "" {
		username = identity.UsernameFromEmail(email)
		if username == "" {
			return nil, fmt.Errorf("%w: cannot derive username from %q", ErrInvalidUsername, email)
		}
	}
	normalizedUser, err := identity.NormalizeUsername(username)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUsername, err)
	}

	nickname := identity.NormalizeNickname(input.Nickname, identity.NormalizeNickname(input.DisplayName, normalizedUser))

	if err := s.pwPolicy.Validate(input.Password); err != nil {
		return nil, err
	}

	hash, err := HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := s.now()
	user := &store.User{
		Username:        normalizedUser,
		Nickname:        nickname,
		Email:           email,
		EmailVerifiedAt: &now,
		PasswordHash:    hash,
		DisplayName:     nickname,
		Status:          store.UserStatusActive,
	}

	var provisionedMembers []store.TenantMember
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		if s.policy != nil {
			members, err := s.policy.Apply(ctx, tx, user.ID)
			if err != nil {
				return err
			}
			provisionedMembers = members
		}
		return nil
	}); err != nil {
		// GORM doesn't surface driver-specific unique-violation codes uniformly
		// across MySQL/SQLite, so we string-match instead. The error text from
		// each driver still mentions "unique"/"duplicate" plus the column name.
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "unique") || strings.Contains(lower, "duplicate") {
			if strings.Contains(lower, "username") {
				return nil, ErrUsernameAlreadyUsed
			}
			return nil, ErrEmailAlreadyUsed
		}
		return nil, err
	}
	if err := provisioning.RecordMembershipAudits(ctx, s.audit, provisionedMembers); err != nil {
		return nil, err
	}

	_ = s.redis.Del(ctx, emailCodeKey(purpose, email)).Err()
	return user, nil
}

// Login authenticates a user by email (or username) and password.
//
// Flow: lookup user → check lockout → verify password → reset lockout → audit.
// Callers (handler.login) are responsible for issuing tokens and setting cookies.
//
// Call chain: handler.login → service.Login → repo.FindByEmail + lockout.Check + audit.Record
func (s *Service) Login(ctx context.Context, input LoginInput) (*store.User, error) {
	identifier := strings.TrimSpace(input.Identifier)
	identifierType := "unknown"

	var user store.User
	if identifier != "" {
		identifierType = loginIdentifierType(identifier)
		var err error
		if identity.IsUsernameLikeIdentifier(identifier) {
			user, err = s.lookupUserByUsername(ctx, identifier)
		} else {
			user, err = s.lookupUserByEmail(ctx, identifier)
		}
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrInvalidCredential
			}
			return nil, err
		}
	} else {
		// Legacy fallback: email field
		identifierType = "email"
		var err error
		user, err = s.lookupUserByEmail(ctx, input.Email)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, ErrInvalidCredential
			}
			return nil, err
		}
	}

	if user.Status == store.UserStatusDisabled {
		return nil, ErrUserDisabled
	}

	// Check account lockout before verifying password.
	if s.lockout != nil {
		locked, remaining, err := s.lockout.IsLocked(ctx, user.ID)
		if err != nil {
			return nil, fmt.Errorf("check lockout: %w", err)
		}
		if locked {
			return nil, fmt.Errorf("%w: retry after %d seconds", ErrAccountLocked, remaining)
		}
	}

	if err := CheckPassword(user.PasswordHash, input.Password); err != nil {
		// Record failure and potentially lock the account.
		if s.lockout != nil {
			nowLocked, _, _ := s.lockout.RecordFailure(ctx, user.ID)
			_ = s.audit.Record(ctx, audit.Entry{
				ActorUserID: user.ID,
				Action:      "login_failed",
				TargetType:  audit.TargetTypeUser,
				TargetID:    audit.UserTargetID(user.ID),
				Metadata:    map[string]any{"identifier_type": identifierType},
			})
			if nowLocked {
				_ = s.audit.Record(ctx, audit.Entry{
					ActorUserID: user.ID,
					Action:      "account_locked",
					TargetType:  audit.TargetTypeUser,
					TargetID:    audit.UserTargetID(user.ID),
					Metadata:    map[string]any{"reason": "consecutive_failures"},
				})
			}
		}
		return nil, ErrInvalidCredential
	}

	// Successful login — clear failure counter.
	if s.lockout != nil {
		_ = s.lockout.Reset(ctx, user.ID)
	}

	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: user.ID,
		Action:      audit.ActionLogin,
		TargetType:  audit.TargetTypeUser,
		TargetID:    audit.UserTargetID(user.ID),
		Metadata: map[string]any{
			"identifier_type": identifierType,
		},
	}); err != nil {
		return nil, err
	}
	return &user, nil
}

// lookupUserByEmail resolves a user by their normalized email address.
//
// Call chain: Login → lookupUserByEmail → repo.FindByEmail
func (s *Service) lookupUserByEmail(ctx context.Context, email string) (store.User, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return store.User{}, err
	}
	return *user, nil
}

// lookupUserByUsername normalizes the raw input then resolves by username.
//
// Call chain: Login → lookupUserByUsername → NormalizeUsername + repo.FindByUsername
func (s *Service) lookupUserByUsername(ctx context.Context, raw string) (store.User, error) {
	username, err := identity.NormalizeUsername(raw)
	if err != nil {
		return store.User{}, gorm.ErrRecordNotFound
	}
	user, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		return store.User{}, err
	}
	return *user, nil
}

// loginIdentifierType classifies a login identifier as "username" or "email".
func loginIdentifierType(identifier string) string {
	if identity.IsUsernameLikeIdentifier(identifier) {
		return "username"
	}
	return "email"
}

// ForgotPassword sends a password-reset code via email. It does not reveal
// whether the email exists (constant-time-like response).
//
// Call chain: handler.forgotPassword → service.ForgotPassword → SendEmailCode(password_forgot)
func (s *Service) ForgotPassword(ctx context.Context, email string) error {
	_, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	_, err = s.SendEmailCode(ctx, EmailCodePurposePasswordReset, email)
	return err
}

// ResetPassword validates the email code and updates the password hash.
//
// Call chain: handler.resetPassword → service.ResetPassword → requireEmailCode → repo.UpdatePassword
func (s *Service) ResetPassword(ctx context.Context, input ResetPasswordInput) error {
	email := identity.NormalizeEmail(input.Email)
	if err := s.requireEmailCode(ctx, EmailCodePurposePasswordReset, email, input.EmailCode); err != nil {
		return err
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidCredential
		}
		return err
	}

	if err := s.pwPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	// Check password history.
	if s.pwPolicy.HistoryCount > 0 {
		var historyHashes []string
		s.db.WithContext(ctx).
			Model(&store.PasswordHistory{}).
			Where("user_id = ?", user.ID).
			Order("created_at DESC").
			Limit(s.pwPolicy.HistoryCount).
			Pluck("password_hash", &historyHashes)
		// Also check current password.
		historyHashes = append([]string{user.PasswordHash}, historyHashes...)
		if err := s.pwPolicy.CheckHistory(input.NewPassword, historyHashes); err != nil {
			return err
		}
	}

	hash, err := HashPassword(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Bump token_version so every existing access token / refresh token for this
	// user is rejected on next use — password reset must invalidate sessions
	// system-wide, even ones we don't have direct revoke handles to.
	result := s.db.WithContext(ctx).Model(&store.User{}).Where("email = ?", email).Updates(map[string]any{
		"password_hash": hash,
		"token_version": gorm.Expr("token_version + 1"),
		"updated_at":    s.now(),
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrInvalidCredential
	}

	// Record old password in history.
	if s.pwPolicy.HistoryCount > 0 {
		_ = s.db.WithContext(ctx).Create(&store.PasswordHistory{
			UserID:       user.ID,
			PasswordHash: user.PasswordHash,
			CreatedAt:    s.now(),
		}).Error
	}

	_ = s.redis.Del(ctx, emailCodeKey(EmailCodePurposePasswordReset, email)).Err()
	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: user.ID,
		Action:      audit.ActionPasswordReset,
		TargetType:  audit.TargetTypeUser,
		TargetID:    audit.UserTargetID(user.ID),
		Metadata: map[string]any{
			"source": "self_service",
		},
	}); err != nil {
		return err
	}
	return nil
}

// requireEmailCode looks up a stored code in Redis, verifies it matches, and
// deletes it on success. Used by Register and ResetPassword as a shared
// verification gate.
func (s *Service) requireEmailCode(ctx context.Context, purpose, email, code string) error {
	storedCode, err := loadEmailCode(ctx, s.redis, purpose, email)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrInvalidEmailCode
		}
		return err
	}
	if storedCode != strings.TrimSpace(code) {
		return ErrInvalidEmailCode
	}
	return nil
}

// emailCodeKey builds the Redis key for an email verification code.
func emailCodeKey(purpose, email string) string {
	return fmt.Sprintf("auth:email_code:%s:%s", purpose, email)
}
