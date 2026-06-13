// Package oidc implements an OAuth 2.0 / OpenID Connect provider: authorization
// endpoint, token endpoint (authorization_code + refresh_token grants), PKCE,
// introspection (RFC 7662), revocation, JWKS, discovery, and RP-initiated logout.
//
// Call chain (inbound → handler → service → persistence):
//
//	authorize.go  →  service.authorize  →  validateClient + createAuthCode
//	token.go      →  service.token      →  validateAuthCode / validateRefreshToken
//	userinfo.go   →  service.userInfo   →  validateAccessToken + loadUser
//	jwks.go       →  service.jwksPublicKeys
//	discovery.go  →  (static config)
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/jwtkey"
	"goauth/services/identity-service/internal/ratelimit"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	defaultAuthorizationCodeTTL = 10 * time.Minute
	defaultAccessTokenTTL       = 15 * time.Minute
	defaultRefreshTokenTTL      = 30 * 24 * time.Hour
	authMethodClientSecretBasic = "client_secret_basic"
	authMethodClientSecretPost  = "client_secret_post"
	accessTokenUseOIDC          = "oidc_access"
)

var errInvalidClientCredentials = errors.New("invalid client credentials")

type Service struct {
	db                   *gorm.DB
	privateKey           *rsa.PrivateKey
	publicKey            *rsa.PublicKey
	keyring              *jwtkey.Keyring
	issuer               string
	browserLoginURL      string
	browserCookieSecure  bool
	keyID                string
	accessTokenTTL       time.Duration
	refreshTokenTTL      time.Duration
	authorizationCodeTTL time.Duration
	rateLimiter          *ratelimit.Service
	audit                audit.Recorder
	now                  func() time.Time
}

type Handler struct {
	service *Service
}

// Dependencies holds optional collaborators for oidc.Service.
type Dependencies struct {
	Audit           audit.Recorder
	RateLimiter     *ratelimit.Service
	BrowserLoginURL string
}

// SetDependencies injects optional dependencies. Use constructor injection
// once Phase 2 is complete for all services.
func (s *Service) SetDependencies(deps Dependencies) {
	s.audit = deps.Audit
	if s.audit == nil {
		s.audit = audit.NoopRecorder{}
	}
	s.rateLimiter = deps.RateLimiter
	s.browserLoginURL = deps.BrowserLoginURL
}

type accessClaims struct {
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Username          string `json:"username,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Scope             string `json:"scope,omitempty"`
	TokenUse          string `json:"token_use,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
	TenantID          int64  `json:"tid,omitempty"`
	SessionID         string `json:"sid,omitempty"`
	TokenVersion      int    `json:"ver,omitempty"`
	jwt.RegisteredClaims
}

type idTokenClaims struct {
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Username          string `json:"username,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

func NewService(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) *Service {
	var keyring *jwtkey.Keyring
	if privateKey != nil {
		keyring, _ = jwtkey.NewKeyring(cfg.JWTKeyID, map[string]*rsa.PrivateKey{cfg.JWTKeyID: privateKey})
	}
	return NewServiceWithKeyring(db, cfg, keyring)
}

func NewServiceWithKeyring(db *gorm.DB, cfg config.Config, keyring *jwtkey.Keyring) *Service {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.PublicIssuerURL), "/")
	if issuer == "" {
		issuer = "http://127.0.0.1:8080"
	}

	accessTokenTTL := cfg.AccessTokenTTL
	if accessTokenTTL <= 0 {
		accessTokenTTL = defaultAccessTokenTTL
	}

	refreshTokenTTL := cfg.RefreshTokenTTL
	if refreshTokenTTL <= 0 {
		refreshTokenTTL = defaultRefreshTokenTTL
	}

	service := &Service{
		db:                   db,
		privateKey:           nil,
		keyring:              keyring,
		issuer:               issuer,
		browserCookieSecure:  cfg.BrowserCookieSecure,
		keyID:                "",
		accessTokenTTL:       accessTokenTTL,
		refreshTokenTTL:      refreshTokenTTL,
		authorizationCodeTTL: defaultAuthorizationCodeTTL,
		audit:                audit.NoopRecorder{},
		now:                  time.Now,
	}
	if keyring != nil {
		service.privateKey = keyring.ActivePrivateKey()
		service.publicKey = keyring.ActivePublicKey()
		service.keyID = keyring.ActiveKeyID()
	}
	return service
}

// Deprecated: use SetDependencies.
func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

// Deprecated: use SetDependencies.
func (s *Service) SetBrowserLoginURL(loginURL string) {
	s.browserLoginURL = strings.TrimSpace(loginURL)
}

func RegisterRoutes(router gin.IRoutes, service *Service) {
	(&Handler{service: service}).RegisterRoutes(router)
}

func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.GET("/.well-known/openid-configuration", h.discovery)
	router.GET("/oauth2/jwks", h.jwks)
	router.GET("/oauth2/authorize", h.authorize)
	router.POST("/oauth2/token", h.token)
	router.GET("/oauth2/userinfo", h.userInfo)
	router.POST("/oauth2/introspect", h.introspect)
	router.POST("/oauth2/revoke", h.revoke)
	router.GET("/oauth2/logout", h.logout)
	router.POST("/oauth2/logout", h.logoutPost)
}

func (s *Service) jwksPublicKeys() []jwtkey.PublicKey {
	if s == nil {
		return nil
	}
	if s.keyring != nil {
		return s.keyring.PublicKeys()
	}
	if s.publicKey == nil {
		return nil
	}
	return []jwtkey.PublicKey{{ID: s.keyID, Key: s.publicKey}}
}

func (s *Service) hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Service) hashAuthorizationCode(raw string) string {
	return s.hashToken(raw)
}

func (s *Service) randomID(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// loadUser fetches a user by primary key (may return soft-deleted or disabled).
//
// Call chain: authorize / exchangeAuthorizationCode → loadUser → DB First
func (s *Service) loadUser(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// loadActiveUser fetches a user that is active and not soft-deleted.
//
// Call chain: refreshToken / validateAccessClaims → loadActiveUser → DB query
func (s *Service) loadActiveUser(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// hasActiveSession checks whether the user has at least one non-revoked refresh
// token for the given session, joined through the login_sessions table.
//
// Call chain: validateAccessClaims / exchangeAuthorizationCode → hasActiveSession → hasActiveSessionWithDB
func (s *Service) hasActiveSession(ctx context.Context, userID int64, sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if userID == 0 || sessionID == "" {
		return false
	}
	return s.hasActiveSessionWithDB(ctx, s.db, userID, sessionID)
}

// hasActiveSessionWithDB is the DB-backed check for an active session row +
// non-revoked refresh token with matching token version.
//
// Call chain: hasActiveSession / exchangeAuthorizationCode → hasActiveSessionWithDB → DB Count
func (s *Service) hasActiveSessionWithDB(ctx context.Context, db *gorm.DB, userID int64, sessionID string) bool {
	var count int64
	err := db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Joins("JOIN login_sessions ON login_sessions.id = refresh_tokens.session_id").
		Joins("JOIN users ON users.id = refresh_tokens.user_id").
		Where("refresh_tokens.user_id = ? AND refresh_tokens.session_id = ? AND refresh_tokens.revoked_at IS NULL AND refresh_tokens.expires_at > ?", userID, sessionID, s.now()).
		Where("login_sessions.revoked_at IS NULL").
		Where("refresh_tokens.token_version = users.token_version AND users.status = ? AND users.deleted_at IS NULL", store.UserStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

// lockActiveSessionWithDB takes a SELECT FOR UPDATE on the login session to
// serialise concurrent token exchanges.
//
// Call chain: exchangeAuthorizationCode / refreshToken → lockActiveSessionWithDB → DB SELECT FOR UPDATE
func (s *Service) lockActiveSessionWithDB(ctx context.Context, db *gorm.DB, userID int64, sessionID string) error {
	var loginSession store.LoginSession
	return db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", sessionID, userID).
		First(&loginSession).Error
}

// hasActiveLoginSessionWithDB checks for a non-revoked login session row.
func (s *Service) hasActiveLoginSessionWithDB(ctx context.Context, db *gorm.DB, userID int64, sessionID string) bool {
	var count int64
	err := db.WithContext(ctx).
		Model(&store.LoginSession{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", sessionID, userID).
		Count(&count).Error
	return err == nil && count > 0
}

// hasActiveTenantMembership checks for an active tenant membership.
func (s *Service) hasActiveTenantMembership(ctx context.Context, userID, tenantID int64) bool {
	if userID == 0 || tenantID == 0 {
		return false
	}

	if !s.hasActiveTenant(ctx, tenantID) {
		return false
	}

	var count int64
	err := s.db.WithContext(ctx).
		Model(&store.TenantMember{}).
		Where("user_id = ? AND tenant_id = ? AND status = ? AND deleted_at IS NULL", userID, tenantID, store.MemberStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

// ensureClientTenantMembership checks whether the user is already a member of
// the client's tenant. If not and the client has AutoProvisionMembers enabled,
// it creates the membership on the fly. This only applies to first-time access
// via trusted internal apps; previously removed/disabled memberships are not
// restored to respect explicit access decisions.
func (s *Service) ensureClientTenantMembership(ctx context.Context, userID int64, client *store.OAuthClient) (bool, error) {
	if client == nil || userID == 0 || client.TenantID == 0 {
		return false, nil
	}
	if s.hasActiveTenantMembership(ctx, userID, client.TenantID) {
		return true, nil
	}
	if !client.AutoProvisionMembers {
		return false, nil
	}
	if _, err := s.loadActiveUser(ctx, userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	if !s.hasActiveTenant(ctx, client.TenantID) {
		return false, nil
	}

	var existingCount int64
	if err := s.db.WithContext(ctx).
		Unscoped().
		Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ?", client.TenantID, userID).
		Count(&existingCount).Error; err != nil {
		return false, err
	}
	if existingCount > 0 {
		// Existing inactive or deleted memberships are explicit access decisions.
		return false, nil
	}

	member := store.TenantMember{
		TenantID: client.TenantID,
		UserID:   userID,
		Status:   store.MemberStatusActive,
	}
	if err := s.db.WithContext(ctx).Create(&member).Error; err != nil {
		if s.hasActiveTenantMembership(ctx, userID, client.TenantID) {
			return true, nil
		}
		if lookupErr := s.db.WithContext(ctx).
			Unscoped().
			Model(&store.TenantMember{}).
			Where("tenant_id = ? AND user_id = ?", client.TenantID, userID).
			Count(&existingCount).Error; lookupErr == nil && existingCount > 0 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// hasActiveTenant checks for an active, non-deleted tenant.
func (s *Service) hasActiveTenant(ctx context.Context, tenantID int64) bool {
	var count int64
	err := s.db.WithContext(ctx).
		Model(&store.Tenant{}).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, store.TenantStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

// validateAccessClaims performs live state checks on an OIDC access token:
// issuer, audience, token_use, user active, token_version, session, membership,
// and client status.
//
// Call chain: userInfo / introspect → validateAccessClaims → loadActiveUser + hasActiveSession + hasActiveTenantMembership
func (s *Service) validateAccessClaims(ctx context.Context, claims accessClaims) error {
	if claims.Issuer != s.issuer {
		return gorm.ErrRecordNotFound
	}
	if strings.TrimSpace(claims.ClientID) == "" || !audienceContains(claims.Audience, claims.ClientID) {
		return gorm.ErrRecordNotFound
	}
	if claims.TokenUse != accessTokenUseOIDC {
		return gorm.ErrRecordNotFound
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return err
	}

	user, err := s.loadActiveUser(ctx, userID)
	if err != nil {
		return err
	}
	if user.TokenVersion != claims.TokenVersion {
		return gorm.ErrRecordNotFound
	}
	if strings.TrimSpace(claims.SessionID) == "" || !s.hasActiveSession(ctx, userID, claims.SessionID) {
		return gorm.ErrRecordNotFound
	}
	if claims.TenantID != 0 && !s.hasActiveTenantMembership(ctx, userID, claims.TenantID) {
		return gorm.ErrRecordNotFound
	}
	client, err := s.loadClient(ctx, claims.ClientID)
	if err != nil {
		return err
	}
	if client.Status != store.UserStatusActive || client.TenantID != claims.TenantID {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// validateRefreshToken validates a refresh token row against live user/session state.
func (s *Service) validateRefreshToken(ctx context.Context, token store.RefreshToken) bool {
	if token.RevokedAt != nil || token.ExpiresAt.Before(s.now()) {
		return false
	}
	if strings.TrimSpace(token.SessionID) == "" {
		return false
	}

	user, err := s.loadActiveUser(ctx, token.UserID)
	if err != nil {
		return false
	}
	if user.TokenVersion != token.TokenVersion {
		return false
	}
	if !s.hasActiveLoginSessionWithDB(ctx, s.db, token.UserID, token.SessionID) {
		return false
	}
	if token.TenantID != 0 && !s.hasActiveTenantMembership(ctx, token.UserID, token.TenantID) {
		return false
	}
	return true
}

// resolvePostLogoutRedirectURI validates the client and redirect URI for RP-initiated logout.
func (s *Service) resolvePostLogoutRedirectURI(ctx context.Context, clientID, redirectURI string) (string, error) {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return "", nil
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", errInvalidClientCredentials
	}

	client, err := s.loadClient(ctx, clientID)
	if err != nil {
		return "", err
	}
	if client.Status != store.UserStatusActive || !s.validateRedirectURI(client, redirectURI) {
		return "", errInvalidClientCredentials
	}
	return redirectURI, nil
}

// parseAccessToken verifies and decodes a JWT access token, supporting both
// single-key and keyring verification.
//
// Call chain: userInfo / introspect → parseAccessToken → jwt.ParseWithClaims
func (s *Service) parseAccessToken(rawToken string) (*accessClaims, error) {
	if s.keyring == nil && s.publicKey == nil {
		return nil, errors.New("missing public key")
	}

	keyfunc := func(token *jwt.Token) (any, error) {
		if s.keyring != nil {
			return s.keyring.Keyfunc(token)
		}
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected signing method")
		}
		return s.publicKey, nil
	}
	token, err := jwt.ParseWithClaims(rawToken, &accessClaims{}, func(token *jwt.Token) (any, error) {
		return keyfunc(token)
	}, jwt.WithIssuer(s.issuer))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// audienceContains reports whether a JWT audience claim includes the given value.
func audienceContains(audience jwt.ClaimStrings, value string) bool {
	for _, item := range audience {
		if item == value {
			return true
		}
	}
	return false
}

// scopeSet converts a space-delimited scope string into a set for O(1) lookups.
func scopeSet(scope string) map[string]struct{} {
	values := splitScope(scope)
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

// hasScope reports whether a scope set contains the given value.
func hasScope(scopes map[string]struct{}, value string) bool {
	_, ok := scopes[value]
	return ok
}
