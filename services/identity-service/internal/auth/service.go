package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"example.com/identity-service/internal/audit"
	"example.com/identity-service/internal/mailer"
	"example.com/identity-service/internal/store"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var (
	ErrInvalidEmailCode  = errors.New("invalid email code")
	ErrEmailAlreadyUsed  = errors.New("email already exists")
	ErrInvalidCredential = errors.New("invalid credentials")
	ErrUserDisabled      = errors.New("user disabled")
)

type MailMessage = mailer.Message
type MailSender = mailer.Sender

type RegisterInput struct {
	Email       string
	DisplayName string
	Password    string
	EmailCode   string
	CodePurpose string
}

type LoginInput struct {
	Email    string
	Password string
}

type ResetPasswordInput struct {
	Email       string
	NewPassword string
	EmailCode   string
}

type Service struct {
	db     *gorm.DB
	redis  *redis.Client
	mailer MailSender
	audit  audit.Recorder
	now    func() time.Time
}

func NewService(db *gorm.DB, redisClient *redis.Client, mailSender MailSender) *Service {
	if mailSender == nil {
		mailSender = mailer.NoopSender{}
	}

	return &Service{
		db:     db,
		redis:  redisClient,
		mailer: mailSender,
		audit:  audit.NoopRecorder{},
		now:    time.Now,
	}
}

func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

func (s *Service) SendEmailCode(ctx context.Context, purpose, email string) (string, error) {
	code, err := generateEmailCode()
	if err != nil {
		return "", fmt.Errorf("generate email code: %w", err)
	}
	if err := storeEmailCode(ctx, s.redis, purpose, normalizeEmail(email), code); err != nil {
		return "", fmt.Errorf("store email code: %w", err)
	}
	if err := s.mailer.Send(ctx, MailMessage{
		To:      normalizeEmail(email),
		Subject: "GoAuth verification code",
		Body:    code,
	}); err != nil {
		return "", fmt.Errorf("send email code: %w", err)
	}
	return code, nil
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*store.User, error) {
	email := normalizeEmail(input.Email)
	if err := s.requireEmailCode(ctx, input.CodePurpose, email, input.EmailCode); err != nil {
		return nil, err
	}

	hash, err := HashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := s.now()
	user := &store.User{
		Email:           email,
		EmailVerifiedAt: &now,
		PasswordHash:    hash,
		DisplayName:     strings.TrimSpace(input.DisplayName),
		Status:          store.UserStatusActive,
	}
	if user.DisplayName == "" {
		user.DisplayName = email
	}

	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return nil, ErrEmailAlreadyUsed
		}
		return nil, err
	}

	_ = s.redis.Del(ctx, emailCodeKey(input.CodePurpose, email)).Err()
	return user, nil
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).Where("email = ?", normalizeEmail(input.Email)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredential
		}
		return nil, err
	}
	if user.Status == store.UserStatusDisabled {
		return nil, ErrUserDisabled
	}
	if err := CheckPassword(user.PasswordHash, input.Password); err != nil {
		return nil, ErrInvalidCredential
	}
	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: user.ID,
		Action:      audit.ActionLogin,
		TargetType:  audit.TargetTypeUser,
		TargetID:    audit.UserTargetID(user.ID),
		Metadata: map[string]any{
			"email": user.Email,
		},
	}); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) ForgotPassword(ctx context.Context, email string) error {
	var user store.User
	if err := s.db.WithContext(ctx).Where("email = ?", normalizeEmail(email)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	_, err := s.SendEmailCode(ctx, EmailCodePurposePasswordReset, email)
	return err
}

func (s *Service) ResetPassword(ctx context.Context, input ResetPasswordInput) error {
	email := normalizeEmail(input.Email)
	if err := s.requireEmailCode(ctx, EmailCodePurposePasswordReset, email, input.EmailCode); err != nil {
		return err
	}

	var user store.User
	if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrInvalidCredential
		}
		return err
	}

	hash, err := HashPassword(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

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

func emailCodeKey(purpose, email string) string {
	return fmt.Sprintf("auth:email_code:%s:%s", purpose, email)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
