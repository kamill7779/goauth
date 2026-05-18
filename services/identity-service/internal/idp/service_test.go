package idp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/provisioning"
	"goauth/services/identity-service/internal/store"
)

type fakeProvider struct {
	slug        string
	displayName string
	token       *TokenSet
	profile     *ExternalProfile

	exchangedCode        string
	exchangedRedirectURI string
	exchangedState       string
}

func (p *fakeProvider) Slug() string {
	return p.slug
}

func (p *fakeProvider) DisplayName() string {
	return p.displayName
}

func (p *fakeProvider) AuthCodeURL(state string, _ AuthCodeOptions) (string, error) {
	return "https://provider.example.test/auth?state=" + state, nil
}

func (p *fakeProvider) ExchangeCode(_ context.Context, code string, redirectURI string, state string) (*TokenSet, error) {
	p.exchangedCode = code
	p.exchangedRedirectURI = redirectURI
	p.exchangedState = state
	return p.token, nil
}

func (p *fakeProvider) FetchProfile(_ context.Context, _ *TokenSet) (*ExternalProfile, error) {
	return p.profile, nil
}

func newTestService(t *testing.T, provider Provider) *Service {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	return NewService(db, provider)
}

func createTestUser(t *testing.T, service *Service, email string) *store.User {
	t.Helper()

	user := &store.User{
		Email:        email,
		DisplayName:  "Test User",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := service.db.Create(user).Error; err != nil {
		t.Fatalf("service.db.Create(user) error = %v", err)
	}
	return user
}

func createTestUserWithStatus(t *testing.T, service *Service, email, status string) *store.User {
	t.Helper()

	user := &store.User{
		Email:        email,
		DisplayName:  "Test User",
		PasswordHash: "hash",
		Status:       status,
	}
	if err := service.db.Create(user).Error; err != nil {
		t.Fatalf("service.db.Create(user) error = %v", err)
	}
	return user
}

func TestAuthenticateReturnsLinkedUser(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	user := createTestUser(t, service, "octocat@example.com")

	identity := &store.UserIdentity{
		UserID:         user.ID,
		Provider:       "github",
		ProviderUserID: "42",
		Email:          "octocat@example.com",
		EmailVerified:  true,
		Username:       "octocat",
		DisplayName:    "The Octocat",
	}
	if err := service.db.Create(identity).Error; err != nil {
		t.Fatalf("service.db.Create(identity) error = %v", err)
	}

	result, err := service.Authenticate(context.Background(), "github", "oauth-code", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.User.ID != user.ID {
		t.Fatalf("result.User.ID = %d, want %d", result.User.ID, user.ID)
	}
	if result.Identity.ProviderUserID != "42" {
		t.Fatalf("result.Identity.ProviderUserID = %q, want 42", result.Identity.ProviderUserID)
	}
	if provider.exchangedRedirectURI != "https://app.example.com/callback" {
		t.Fatalf("redirect URI = %q, want callback URI", provider.exchangedRedirectURI)
	}
}

func TestAuthenticateRejectsDisabledLinkedUser(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	user := createTestUserWithStatus(t, service, "octocat@example.com", store.UserStatusDisabled)

	identity := &store.UserIdentity{
		UserID:         user.ID,
		Provider:       "github",
		ProviderUserID: "42",
		Email:          "octocat@example.com",
		EmailVerified:  true,
		Username:       "octocat",
		DisplayName:    "The Octocat",
	}
	if err := service.db.Create(identity).Error; err != nil {
		t.Fatalf("service.db.Create(identity) error = %v", err)
	}

	_, err := service.Authenticate(context.Background(), "github", "oauth-code", "https://app.example.com/callback")
	if !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrUserDisabled)
	}
}

func TestAuthenticateRequiresLocalLoginWhenEmailExistsWithoutIdentity(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	createTestUser(t, service, "octocat@example.com")

	_, err := service.Authenticate(context.Background(), "github", "oauth-code", "")
	if !errors.Is(err, ErrLocalLoginRequired) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrLocalLoginRequired)
	}

	var count int64
	if err := service.db.Model(&store.UserIdentity{}).Count(&count).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if count != 0 {
		t.Fatalf("identity count = %d, want 0", count)
	}
}

func TestAuthenticateRejectsNewExternalUserWhenRegistrationNotOpen(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	service.SetRegistrationMode("invite_only")

	_, err := service.Authenticate(context.Background(), "github", "oauth-code", "https://app.example.com/callback")
	if !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrRegistrationDisabled)
	}
}

func TestAuthenticateRecordsAuditLogForLinkedUser(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	service.SetAuditRecorder(audit.NewService(service.db))
	user := createTestUser(t, service, "octocat@example.com")
	identity := &store.UserIdentity{
		UserID:         user.ID,
		Provider:       "github",
		ProviderUserID: "42",
		Email:          "octocat@example.com",
		EmailVerified:  true,
		Username:       "octocat",
		DisplayName:    "The Octocat",
	}
	if err := service.db.Create(identity).Error; err != nil {
		t.Fatalf("service.db.Create(identity) error = %v", err)
	}

	result, err := service.Authenticate(context.Background(), "github", "oauth-code", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.User.ID != user.ID {
		t.Fatalf("result.User.ID = %d, want %d", result.User.ID, user.ID)
	}

	var log store.AuditLog
	if err := service.db.Where("action = ?", audit.ActionLogin).First(&log).Error; err != nil {
		t.Fatalf("load audit log: %v", err)
	}
	if log.TargetType != audit.TargetTypeUser {
		t.Fatalf("log.TargetType = %q, want %q", log.TargetType, audit.TargetTypeUser)
	}
	if log.TargetID != audit.UserTargetID(user.ID) {
		t.Fatalf("log.TargetID = %q, want %q", log.TargetID, audit.UserTargetID(user.ID))
	}

	var metadata map[string]any
	if err := json.Unmarshal(log.Metadata, &metadata); err != nil {
		t.Fatalf("json.Unmarshal(metadata) error = %v", err)
	}
	if metadata["provider"] != "github" {
		t.Fatalf("metadata provider = %v, want github", metadata["provider"])
	}
	if metadata["created"] != false {
		t.Fatalf("metadata created = %v, want false", metadata["created"])
	}
}

func TestAuthenticateRecordsAuditLogForCreatedUser(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	service.SetAuditRecorder(audit.NewService(service.db))

	result, err := service.Authenticate(context.Background(), "github", "oauth-code", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !result.Created {
		t.Fatal("expected created user result")
	}

	var log store.AuditLog
	if err := service.db.Where("action = ?", audit.ActionLogin).First(&log).Error; err != nil {
		t.Fatalf("load audit log: %v", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal(log.Metadata, &metadata); err != nil {
		t.Fatalf("json.Unmarshal(metadata) error = %v", err)
	}
	if metadata["provider"] != "github" {
		t.Fatalf("metadata provider = %v, want github", metadata["provider"])
	}
	if metadata["created"] != true {
		t.Fatalf("metadata created = %v, want true", metadata["created"])
	}
}

func TestAuthenticateAppliesDefaultMembershipPolicyForCreatedUser(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	tenantRecord := store.Tenant{Name: "Community", Slug: "community", Status: store.TenantStatusActive}
	if err := service.db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	service.SetDefaultMembershipPolicy(provisioning.NewDefaultMembershipPolicy([]string{"community"}))

	result, err := service.Authenticate(context.Background(), "github", "oauth-code", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ? AND status = ?", tenantRecord.ID, result.User.ID, store.MemberStatusActive).
		Count(&count).Error; err != nil {
		t.Fatalf("count tenant members: %v", err)
	}
	if count != 1 {
		t.Fatalf("active tenant member count = %d, want 1", count)
	}
}

func TestBindLinksGitHubIdentityForLoggedInUser(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
			AvatarURL:      "https://avatars.example.test/octocat.png",
		},
	}
	service := newTestService(t, provider)
	user := createTestUser(t, service, "octocat@example.com")

	identity, err := service.Bind(context.Background(), user.ID, "github", "bind-code", "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if identity.UserID != user.ID {
		t.Fatalf("identity.UserID = %d, want %d", identity.UserID, user.ID)
	}
	if identity.Provider != "github" {
		t.Fatalf("identity.Provider = %q, want github", identity.Provider)
	}
	if identity.ProviderUserID != "42" {
		t.Fatalf("identity.ProviderUserID = %q, want 42", identity.ProviderUserID)
	}

	var stored store.UserIdentity
	if err := service.db.Where("user_id = ? AND provider = ?", user.ID, "github").First(&stored).Error; err != nil {
		t.Fatalf("reload identity: %v", err)
	}
	if stored.Username != "octocat" {
		t.Fatalf("stored.Username = %q, want octocat", stored.Username)
	}
	if stored.AvatarURL != "https://avatars.example.test/octocat.png" {
		t.Fatalf("stored.AvatarURL = %q, want avatar URL", stored.AvatarURL)
	}
}

func TestBindAndUnbindRecordAuditLogs(t *testing.T) {
	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	service.SetAuditRecorder(audit.NewService(service.db))
	user := createTestUser(t, service, "octocat@example.com")

	if _, err := service.Bind(context.Background(), user.ID, "github", "bind-code", "https://app.example.com/callback"); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if err := service.Unbind(context.Background(), user.ID, "github"); err != nil {
		t.Fatalf("Unbind() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.AuditLog{}).
		Where("action = ?", audit.ActionExternalIdentityChanged).
		Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 2 {
		t.Fatalf("external identity audit log count = %d, want 2", count)
	}
}

func TestUnbindRejectsOnlyLoginMethodForExternalOnlyUser(t *testing.T) {
	provider := &fakeProvider{slug: "github", displayName: "GitHub"}
	service := newTestService(t, provider)
	user := &store.User{
		Email:        "external-only@example.com",
		DisplayName:  "External Only",
		PasswordHash: "!external:github",
		Status:       store.UserStatusActive,
	}
	if err := service.db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	identity := &store.UserIdentity{
		UserID:         user.ID,
		Provider:       "github",
		ProviderUserID: "42",
		Email:          user.Email,
	}
	if err := service.db.Create(identity).Error; err != nil {
		t.Fatalf("create identity: %v", err)
	}

	err := service.Unbind(context.Background(), user.ID, "github")
	if err == nil || !strings.Contains(err.Error(), "only remaining login method") {
		t.Fatalf("Unbind() error = %v, want only remaining login method", err)
	}

	var count int64
	if err := service.db.Model(&store.UserIdentity{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if count != 1 {
		t.Fatalf("identity count = %d, want identity preserved", count)
	}
}

func TestUnbindAllowsExternalOnlyUserWithAnotherProvider(t *testing.T) {
	provider := &fakeProvider{slug: "github", displayName: "GitHub"}
	service := newTestService(t, provider)
	user := &store.User{
		Email:        "external-two@example.com",
		DisplayName:  "External Two",
		PasswordHash: "!external:github",
		Status:       store.UserStatusActive,
	}
	if err := service.db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	identities := []store.UserIdentity{
		{UserID: user.ID, Provider: "github", ProviderUserID: "42", Email: user.Email},
		{UserID: user.ID, Provider: "google", ProviderUserID: "84", Email: user.Email},
	}
	if err := service.db.Create(&identities).Error; err != nil {
		t.Fatalf("create identities: %v", err)
	}

	if err := service.Unbind(context.Background(), user.ID, "github"); err != nil {
		t.Fatalf("Unbind() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.UserIdentity{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if count != 1 {
		t.Fatalf("identity count = %d, want remaining provider identity", count)
	}
}
