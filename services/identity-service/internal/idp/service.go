package idp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"example.com/identity-service/internal/audit"
	"example.com/identity-service/internal/store"
	"gorm.io/gorm"
)

var (
	ErrProviderNotFound      = errors.New("provider not found")
	ErrLocalLoginRequired    = errors.New("local login required before binding external identity")
	ErrExternalIdentityInUse = errors.New("external identity already linked to another user")
	ErrProviderAlreadyBound  = errors.New("provider already linked to user")
	ErrIdentityNotFound      = errors.New("identity not found")
	ErrEmailRequired         = errors.New("external profile email required")
	ErrUserDisabled          = errors.New("user disabled")
)

type AuthenticateResult struct {
	User      *store.User
	Identity  *store.UserIdentity
	Created   bool
	TokenSet  *TokenSet
	Profile   *ExternalProfile
	Provider  string
	WasLinked bool
}

type Service struct {
	db        *gorm.DB
	providers map[string]Provider
	audit     audit.Recorder
	now       func() time.Time
}

func NewService(db *gorm.DB, providers ...Provider) *Service {
	providerMap := make(map[string]Provider, len(providers))
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		providerMap[provider.Slug()] = provider
	}

	return &Service{
		db:        db,
		providers: providerMap,
		audit:     audit.NoopRecorder{},
		now:       time.Now,
	}
}

func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

func (s *Service) Start(providerSlug, state string, opts AuthCodeOptions) (string, error) {
	provider, err := s.provider(providerSlug)
	if err != nil {
		return "", err
	}
	return provider.AuthCodeURL(state, opts)
}

func (s *Service) Authenticate(ctx context.Context, providerSlug, code, redirectURI string) (*AuthenticateResult, error) {
	provider, profile, token, err := s.resolveProfile(ctx, providerSlug, code, redirectURI)
	if err != nil {
		return nil, err
	}

	identity, err := s.findIdentity(ctx, provider.Slug(), profile.ProviderUserID)
	if err != nil {
		return nil, err
	}
	var user *store.User
	var createdIdentity *store.UserIdentity
	created := false
	if identity != nil {
		user, err = s.findUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
		}
		if user.Status == store.UserStatusDisabled {
			return nil, ErrUserDisabled
		}
	} else {
		email := normalizeEmail(profile.Email)
		if email == "" {
			return nil, ErrEmailRequired
		}

		user, err = s.findUserByEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		if user != nil {
			return nil, ErrLocalLoginRequired
		}

		err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			now := s.now()
			user = &store.User{
				Email:           email,
				PasswordHash:    "!external:" + provider.Slug(),
				DisplayName:     chooseDisplayName(profile, email),
				AvatarURL:       strings.TrimSpace(profile.AvatarURL),
				Status:          store.UserStatusActive,
				EmailVerifiedAt: nil,
			}
			if profile.EmailVerified {
				user.EmailVerifiedAt = &now
			}
			if err := tx.Create(user).Error; err != nil {
				return err
			}

			createdIdentity = newIdentity(user.ID, provider.Slug(), profile)
			return tx.Create(createdIdentity).Error
		})
		if err != nil {
			return nil, err
		}
		created = true
	}

	if err := s.audit.Record(ctx, audit.Entry{
		ActorUserID: user.ID,
		Action:      audit.ActionLogin,
		TargetType:  audit.TargetTypeUser,
		TargetID:    audit.UserTargetID(user.ID),
		Metadata: map[string]any{
			"provider": provider.Slug(),
			"created":  created,
		},
	}); err != nil {
		return nil, err
	}

	result := &AuthenticateResult{
		User:      user,
		TokenSet:  token,
		Profile:   profile,
		Provider:  provider.Slug(),
		WasLinked: identity != nil,
	}
	if identity != nil {
		result.Identity = identity
	} else {
		result.Identity = createdIdentity
		result.Created = true
	}
	return result, nil
}

func (s *Service) Bind(ctx context.Context, userID int64, providerSlug, code, redirectURI string) (*store.UserIdentity, error) {
	provider, profile, _, err := s.resolveProfile(ctx, providerSlug, code, redirectURI)
	if err != nil {
		return nil, err
	}
	if _, err := s.findUserByID(ctx, userID); err != nil {
		return nil, err
	}

	identity, err := s.findIdentity(ctx, provider.Slug(), profile.ProviderUserID)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		if identity.UserID == userID {
			return identity, nil
		}
		return nil, ErrExternalIdentityInUse
	}

	var existing store.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider.Slug()).
		First(&existing).Error; err == nil {
		if existing.ProviderUserID == profile.ProviderUserID {
			return &existing, nil
		}
		return nil, ErrProviderAlreadyBound
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	identity = newIdentity(userID, provider.Slug(), profile)
	if err := s.db.WithContext(ctx).Create(identity).Error; err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		ActorUserID: userID,
		TargetType:  audit.TargetTypeIdentity,
		TargetID:    strconv.FormatInt(identity.ID, 10),
		Action:      audit.ActionExternalIdentityChanged,
		Metadata: map[string]any{
			"change":            "bound",
			"provider":          identity.Provider,
			"provider_user_id":  identity.ProviderUserID,
			"identity_user_id":  identity.UserID,
			"identity_username": identity.Username,
		},
	})
	return identity, nil
}

func (s *Service) Unbind(ctx context.Context, userID int64, providerSlug string) error {
	var identity store.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, providerSlug).
		First(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrIdentityNotFound
		}
		return err
	}

	result := s.db.WithContext(ctx).Where("id = ?", identity.ID).Delete(&store.UserIdentity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrIdentityNotFound
	}
	_ = s.audit.Record(ctx, audit.Entry{
		ActorUserID: userID,
		TargetType:  audit.TargetTypeIdentity,
		TargetID:    strconv.FormatInt(identity.ID, 10),
		Action:      audit.ActionExternalIdentityChanged,
		Metadata: map[string]any{
			"change":            "unbound",
			"provider":          identity.Provider,
			"provider_user_id":  identity.ProviderUserID,
			"identity_user_id":  identity.UserID,
			"identity_username": identity.Username,
		},
	})
	return nil
}

func (s *Service) ListIdentities(ctx context.Context, userID int64) ([]store.UserIdentity, error) {
	var identities []store.UserIdentity
	if err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("id asc").
		Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

func (s *Service) resolveProfile(ctx context.Context, providerSlug, code, redirectURI string) (Provider, *ExternalProfile, *TokenSet, error) {
	provider, err := s.provider(providerSlug)
	if err != nil {
		return nil, nil, nil, err
	}

	token, err := provider.ExchangeCode(ctx, code, redirectURI)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("exchange code: %w", err)
	}
	profile, err := provider.FetchProfile(ctx, token)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch profile: %w", err)
	}
	if strings.TrimSpace(profile.Provider) == "" {
		profile.Provider = provider.Slug()
	}
	if profile.Provider != provider.Slug() {
		return nil, nil, nil, fmt.Errorf("profile provider mismatch: %s", profile.Provider)
	}
	return provider, profile, token, nil
}

func (s *Service) provider(providerSlug string) (Provider, error) {
	provider, ok := s.providers[providerSlug]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

func (s *Service) findIdentity(ctx context.Context, providerSlug, providerUserID string) (*store.UserIdentity, error) {
	var identity store.UserIdentity
	err := s.db.WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", providerSlug, providerUserID).
		First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func (s *Service) findUserByID(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) findUserByEmail(ctx context.Context, email string) (*store.User, error) {
	var user store.User
	err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func newIdentity(userID int64, providerSlug string, profile *ExternalProfile) *store.UserIdentity {
	return &store.UserIdentity{
		UserID:         userID,
		Provider:       providerSlug,
		ProviderUserID: strings.TrimSpace(profile.ProviderUserID),
		Email:          normalizeEmail(profile.Email),
		EmailVerified:  profile.EmailVerified,
		Username:       strings.TrimSpace(profile.Username),
		DisplayName:    chooseDisplayName(profile, normalizeEmail(profile.Email)),
		AvatarURL:      strings.TrimSpace(profile.AvatarURL),
	}
}

func chooseDisplayName(profile *ExternalProfile, fallback string) string {
	if profile == nil {
		return fallback
	}
	if name := strings.TrimSpace(profile.DisplayName); name != "" {
		return name
	}
	if username := strings.TrimSpace(profile.Username); username != "" {
		return username
	}
	return fallback
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
