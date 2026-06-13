// Package idp integrates third-party identity providers (currently GitHub)
// for external login, identity binding, and code exchange.
//
// Call-chain overview:
//
//	HTTP handlers → Service.Authenticate / Bind / Unbind → Provider.ExchangeCode → Provider.FetchProfile
//	                Service.Authenticate → DB (find-or-create user + identity)
//	                Service.Bind          → DB (link identity to existing user)
//	                Service.Unbind        → DB (remove identity, ensure login method remains)
package idp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"goauth/services/identity-service/internal/audit"
	identitypkg "goauth/services/identity-service/internal/identity"
	"goauth/services/identity-service/internal/provisioning"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrProviderNotFound      = errors.New("provider not found")
	ErrLocalLoginRequired    = errors.New("local login required before binding external identity")
	ErrExternalIdentityInUse = errors.New("external identity already linked to another user")
	ErrProviderAlreadyBound  = errors.New("provider already linked to user")
	ErrIdentityNotFound      = errors.New("identity not found")
	ErrEmailRequired         = errors.New("external profile email required")
	ErrUserDisabled          = errors.New("user disabled")
	ErrRegistrationDisabled  = errors.New("registration disabled")
	ErrOnlyLoginMethod       = errors.New("cannot unbind the only remaining login method")
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

// Service integrates third-party identity providers (currently GitHub) for
// external login, account binding, and OAuth code exchange. It orchestrates
// the full flow from provider redirect through profile resolution to user
// creation or lookup, then delegates token issuance to the session service.
//
// Key methods: Authenticate → ExchangeCode → BindIdentity → UnbindIdentity
type Service struct {
	db               *gorm.DB
	providers        map[string]Provider
	audit            audit.Recorder
	policy           *provisioning.DefaultMembershipPolicy
	now              func() time.Time
	registrationMode string
}

// Dependencies holds optional collaborators for idp.Service.
type Dependencies struct {
	Audit            audit.Recorder
	Policy           *provisioning.DefaultMembershipPolicy
	RegistrationMode string
}

// SetDependencies injects optional dependencies. Use constructor injection
// once Phase 2 is complete for all services.
func (s *Service) SetDependencies(deps Dependencies) {
	s.audit = deps.Audit
	if s.audit == nil {
		s.audit = audit.NoopRecorder{}
	}
	s.policy = deps.Policy
	mode := strings.TrimSpace(deps.RegistrationMode)
	if mode != "" {
		s.registrationMode = strings.ToLower(mode)
	}
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
		db:               db,
		providers:        providerMap,
		audit:            audit.NoopRecorder{},
		now:              time.Now,
		registrationMode: "open",
	}
}

// SetRegistrationMode sets who can register via external identity providers.
//
// Deprecated: use SetDependencies.
func (s *Service) SetRegistrationMode(mode string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "open"
	}
	s.registrationMode = mode
}

// SetDefaultMembershipPolicy sets the default-membership provisioner.
//
// Deprecated: use SetDependencies.
func (s *Service) SetDefaultMembershipPolicy(policy *provisioning.DefaultMembershipPolicy) {
	s.policy = policy
}

// SetAuditRecorder sets the audit recorder; nil resets to no-op.
//
// Deprecated: use SetDependencies.
func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

// Start builds the OAuth authorization URL for the given provider.
//
// Call chain: handler → Start → provider.AuthCodeURL
func (s *Service) Start(providerSlug, state string, opts AuthCodeOptions) (string, error) {
	provider, err := s.provider(providerSlug)
	if err != nil {
		return "", err
	}
	return provider.AuthCodeURL(state, opts)
}

// Authenticate exchanges an authorization code for a user profile and either
// finds the existing linked account, safely auto-binds a verified email match
// to an existing local user, or creates a new user+identity in a single
// transaction.
func (s *Service) Authenticate(ctx context.Context, providerSlug, code, redirectURI string) (*AuthenticateResult, error) {
	return s.authenticate(ctx, providerSlug, code, redirectURI, "")
}

// AuthenticateWithState delegates to authenticate, forwarding the OAuth state
// parameter through to the provider's code-exchange step.
//
// Call chain: handler.callback → AuthenticateWithState → authenticate
func (s *Service) AuthenticateWithState(ctx context.Context, providerSlug, code, redirectURI, state string) (*AuthenticateResult, error) {
	return s.authenticate(ctx, providerSlug, code, redirectURI, state)
}

// authenticate resolves the provider profile, finds or creates the local user
// and identity record in a single transaction, and records audit events.
//
// Call chain: Authenticate / AuthenticateWithState → authenticate → resolveProfile → findIdentity / findUserByEmail → DB (create user + identity)
func (s *Service) authenticate(ctx context.Context, providerSlug, code, redirectURI, state string) (*AuthenticateResult, error) {
	provider, profile, token, err := s.resolveProfile(ctx, providerSlug, code, redirectURI, state)
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
	autoBound := false
	if identity != nil {
		user, err = s.findUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
		}
		if user.Status == store.UserStatusDisabled {
			return nil, ErrUserDisabled
		}
	} else {
		email := identitypkg.NormalizeEmail(profile.Email)
		if email == "" {
			return nil, ErrEmailRequired
		}

		user, err = s.findUserByEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		if user != nil {
			if !profile.EmailVerified {
				return nil, ErrLocalLoginRequired
			}
			if user.Status == store.UserStatusDisabled {
				return nil, ErrUserDisabled
			}
			err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				existingIdentity, err := s.findIdentityForUserAndProvider(ctx, tx, user.ID, provider.Slug())
				if err != nil {
					return err
				}
				if existingIdentity != nil {
					if existingIdentity.ProviderUserID == strings.TrimSpace(profile.ProviderUserID) {
						createdIdentity = existingIdentity
						return nil
					}
					return ErrLocalLoginRequired
				}
				createdIdentity = newIdentity(user.ID, provider.Slug(), profile)
				return tx.Create(createdIdentity).Error
			})
			if err != nil {
				return nil, err
			}
			autoBound = true
		} else {
			if s.registrationMode != "open" {
				return nil, ErrRegistrationDisabled
			}

			var provisionedMembers []store.TenantMember
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
				members, err := s.policy.Apply(ctx, tx, user.ID)
				if err != nil {
					return err
				}
				provisionedMembers = members

				createdIdentity = newIdentity(user.ID, provider.Slug(), profile)
				return tx.Create(createdIdentity).Error
			})
			if err != nil {
				return nil, err
			}
			if err := provisioning.RecordMembershipAudits(ctx, s.audit, provisionedMembers); err != nil {
				return nil, err
			}
			created = true
		}
	}

	if autoBound && createdIdentity != nil {
		_ = s.audit.Record(ctx, audit.Entry{
			ActorUserID: user.ID,
			TargetType:  audit.TargetTypeIdentity,
			TargetID:    strconv.FormatInt(createdIdentity.ID, 10),
			Action:      audit.ActionExternalIdentityChanged,
			Metadata: map[string]any{
				"change":            "auto_bound",
				"provider":          createdIdentity.Provider,
				"provider_user_id":  createdIdentity.ProviderUserID,
				"identity_user_id":  createdIdentity.UserID,
				"identity_username": createdIdentity.Username,
			},
		})
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
		result.Created = created
	}
	return result, nil
}

// Bind links an external identity to an existing authenticated user. Rejects
// if the external identity is already linked to a different user or if the
// user already has a binding for this provider.
func (s *Service) Bind(ctx context.Context, userID int64, providerSlug, code, redirectURI string) (*store.UserIdentity, error) {
	return s.BindWithState(ctx, userID, providerSlug, code, redirectURI, "")
}

// BindWithState links an external identity to the given user, forwarding the
// OAuth state to the code-exchange step.
//
// Call chain: handler.bind / completeBindCallback → BindWithState → resolveProfile → findIdentity → DB (create identity)
func (s *Service) BindWithState(ctx context.Context, userID int64, providerSlug, code, redirectURI, state string) (*store.UserIdentity, error) {
	provider, profile, _, err := s.resolveProfile(ctx, providerSlug, code, redirectURI, state)
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

	existing, err := s.findIdentityForUserAndProvider(ctx, s.db.WithContext(ctx), userID, provider.Slug())
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.ProviderUserID == profile.ProviderUserID {
			return existing, nil
		}
		return nil, ErrProviderAlreadyBound
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

// Unbind removes an external identity from a user, first checking that at
// least one login method (password or another identity) remains.
//
// Call chain: handler.unbind / unbindAccountProvider → Unbind → DB (delete identity, verify login methods)
func (s *Service) Unbind(ctx context.Context, userID int64, providerSlug string) error {
	providerSlug = strings.ToLower(strings.TrimSpace(providerSlug))
	var identity store.UserIdentity
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.
			Where("user_id = ? AND provider = ?", userID, providerSlug).
			First(&identity).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrIdentityNotFound
			}
			return err
		}

		if err := ensureUnbindLeavesLoginMethod(ctx, tx, userID); err != nil {
			return err
		}

		result := tx.Where("id = ?", identity.ID).Delete(&store.UserIdentity{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrIdentityNotFound
		}
		if err := ensureUserHasLoginMethod(ctx, tx, userID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
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

// ensureUnbindLeavesLoginMethod checks that removing the current identity
// won't leave the user without any login method. If the user has a local
// password or more than one identity the check passes.
//
// Call chain: Unbind → ensureUnbindLeavesLoginMethod → DB (count identities)
func ensureUnbindLeavesLoginMethod(ctx context.Context, tx *gorm.DB, userID int64) error {
	var user store.User
	query := tx.WithContext(ctx)
	if tx.Dialector.Name() != "sqlite" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := query.Where("id = ?", userID).First(&user).Error; err != nil {
		return err
	}
	if hasUsableLocalPassword(user.PasswordHash) {
		return nil
	}

	var identityCount int64
	if err := tx.WithContext(ctx).Model(&store.UserIdentity{}).Where("user_id = ?", userID).Count(&identityCount).Error; err != nil {
		return err
	}
	if identityCount <= 1 {
		return ErrOnlyLoginMethod
	}
	return nil
}

// ensureUserHasLoginMethod verifies the user still has at least one usable
// login method after an identity is deleted.
//
// Call chain: Unbind → ensureUserHasLoginMethod → DB (check password / count identities)
func ensureUserHasLoginMethod(ctx context.Context, tx *gorm.DB, userID int64) error {
	var user store.User
	if err := tx.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return err
	}
	if hasUsableLocalPassword(user.PasswordHash) {
		return nil
	}

	var identityCount int64
	if err := tx.WithContext(ctx).Model(&store.UserIdentity{}).Where("user_id = ?", userID).Count(&identityCount).Error; err != nil {
		return err
	}
	if identityCount == 0 {
		return ErrOnlyLoginMethod
	}
	return nil
}

// hasUsableLocalPassword returns true when hash is a real (non-external) password hash.
func hasUsableLocalPassword(hash string) bool {
	hash = strings.TrimSpace(hash)
	return hash != "" && !strings.HasPrefix(hash, "!external:")
}

// ListIdentities returns all external identities linked to the given user.
//
// Call chain: handler.listIdentities → ListIdentities → DB (query identities)
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

// resolveProfile looks up the provider, exchanges the code for a token, and
// fetches the external user profile.
//
// Call chain: authenticate / BindWithState → resolveProfile → provider.ExchangeCode → provider.FetchProfile
func (s *Service) resolveProfile(ctx context.Context, providerSlug, code, redirectURI, state string) (Provider, *ExternalProfile, *TokenSet, error) {
	provider, err := s.provider(providerSlug)
	if err != nil {
		return nil, nil, nil, err
	}

	token, err := provider.ExchangeCode(ctx, code, redirectURI, state)
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

// provider returns the registered Provider for the given slug or
// ErrProviderNotFound.
//
// Call chain: Start / resolveProfile → provider
func (s *Service) provider(providerSlug string) (Provider, error) {
	provider, ok := s.providers[providerSlug]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return provider, nil
}

// findIdentity queries for an external identity by provider + provider user ID.
// Returns nil, nil when not found.
//
// Call chain: authenticate / BindWithState → findIdentity → DB (query identity)
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

// findIdentityForUserAndProvider queries for a specific user's identity with
// the given provider.
//
// Call chain: authenticate / BindWithState → findIdentityForUserAndProvider → DB
func (s *Service) findIdentityForUserAndProvider(ctx context.Context, db *gorm.DB, userID int64, providerSlug string) (*store.UserIdentity, error) {
	var identity store.UserIdentity
	err := db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, providerSlug).
		First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

// findUserByID loads a user by primary key.
//
// Call chain: authenticate / BindWithState / Unbind → findUserByID → DB
func (s *Service) findUserByID(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// findUserByEmail looks up a user by email; returns nil, nil when not found.
//
// Call chain: authenticate → findUserByEmail → DB
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

// newIdentity constructs a UserIdentity record from a profile, normalising
// email and trimming whitespace.
//
// Call chain: authenticate / BindWithState → newIdentity
func newIdentity(userID int64, providerSlug string, profile *ExternalProfile) *store.UserIdentity {
	return &store.UserIdentity{
		UserID:         userID,
		Provider:       providerSlug,
		ProviderUserID: strings.TrimSpace(profile.ProviderUserID),
		Email:          identitypkg.NormalizeEmail(profile.Email),
		EmailVerified:  profile.EmailVerified,
		Username:       strings.TrimSpace(profile.Username),
		DisplayName:    chooseDisplayName(profile, identitypkg.NormalizeEmail(profile.Email)),
		AvatarURL:      strings.TrimSpace(profile.AvatarURL),
	}
}

// chooseDisplayName picks the best display name from a profile: DisplayName >
// Username > fallback.
//
// Call chain: newIdentity / authenticate → chooseDisplayName
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

