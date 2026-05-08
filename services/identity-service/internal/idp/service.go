package idp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
		now:       time.Now,
	}
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
	if identity != nil {
		user, err := s.findUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
		}
		return &AuthenticateResult{
			User:      user,
			Identity:  identity,
			TokenSet:  token,
			Profile:   profile,
			Provider:  provider.Slug(),
			WasLinked: true,
		}, nil
	}

	email := normalizeEmail(profile.Email)
	if email == "" {
		return nil, ErrEmailRequired
	}

	user, err := s.findUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user != nil {
		return nil, ErrLocalLoginRequired
	}

	var createdUser *store.User
	var createdIdentity *store.UserIdentity
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := s.now()
		createdUser = &store.User{
			Email:           email,
			PasswordHash:    "!external:" + provider.Slug(),
			DisplayName:     chooseDisplayName(profile, email),
			AvatarURL:       strings.TrimSpace(profile.AvatarURL),
			Status:          store.UserStatusActive,
			EmailVerifiedAt: nil,
		}
		if profile.EmailVerified {
			createdUser.EmailVerifiedAt = &now
		}
		if err := tx.Create(createdUser).Error; err != nil {
			return err
		}

		createdIdentity = newIdentity(createdUser.ID, provider.Slug(), profile)
		return tx.Create(createdIdentity).Error
	})
	if err != nil {
		return nil, err
	}

	return &AuthenticateResult{
		User:     createdUser,
		Identity: createdIdentity,
		Created:  true,
		TokenSet: token,
		Profile:  profile,
		Provider: provider.Slug(),
	}, nil
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
	return identity, nil
}

func (s *Service) Unbind(ctx context.Context, userID int64, providerSlug string) error {
	result := s.db.WithContext(ctx).Where("user_id = ? AND provider = ?", userID, providerSlug).Delete(&store.UserIdentity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrIdentityNotFound
	}
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
