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
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
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
	issuer               string
	keyID                string
	accessTokenTTL       time.Duration
	refreshTokenTTL      time.Duration
	authorizationCodeTTL time.Duration
	audit                audit.Recorder
	now                  func() time.Time
}

type Handler struct {
	service *Service
}

type accessClaims struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Scope         string `json:"scope,omitempty"`
	TokenUse      string `json:"token_use,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	TenantID      int64  `json:"tid,omitempty"`
	SessionID     string `json:"sid,omitempty"`
	TokenVersion  int    `json:"ver,omitempty"`
	jwt.RegisteredClaims
}

type idTokenClaims struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

func NewService(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) *Service {
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
		privateKey:           privateKey,
		issuer:               issuer,
		keyID:                cfg.JWTKeyID,
		accessTokenTTL:       accessTokenTTL,
		refreshTokenTTL:      refreshTokenTTL,
		authorizationCodeTTL: defaultAuthorizationCodeTTL,
		audit:                audit.NoopRecorder{},
		now:                  time.Now,
	}
	if privateKey != nil {
		service.publicKey = &privateKey.PublicKey
	}
	return service
}

func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
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

func (s *Service) loadUser(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) loadActiveUser(ctx context.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).
		Where("id = ? AND status = ? AND deleted_at IS NULL", userID, store.UserStatusActive).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) hasActiveSession(ctx context.Context, userID int64, sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if userID == 0 || sessionID == "" {
		return false
	}
	return s.hasActiveSessionWithDB(ctx, s.db, userID, sessionID)
}

func (s *Service) hasActiveSessionWithDB(ctx context.Context, db *gorm.DB, userID int64, sessionID string) bool {
	var count int64
	err := db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Joins("JOIN users ON users.id = refresh_tokens.user_id").
		Where("refresh_tokens.user_id = ? AND refresh_tokens.session_id = ? AND refresh_tokens.revoked_at IS NULL AND refresh_tokens.expires_at > ?", userID, sessionID, s.now()).
		Where("refresh_tokens.token_version = users.token_version AND users.status = ? AND users.deleted_at IS NULL", store.UserStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

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

func (s *Service) hasActiveTenant(ctx context.Context, tenantID int64) bool {
	var count int64
	err := s.db.WithContext(ctx).
		Model(&store.Tenant{}).
		Where("id = ? AND status = ? AND deleted_at IS NULL", tenantID, store.TenantStatusActive).
		Count(&count).Error
	return err == nil && count > 0
}

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
	if token.TenantID != 0 && !s.hasActiveTenantMembership(ctx, token.UserID, token.TenantID) {
		return false
	}
	return true
}

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

func (s *Service) parseAccessToken(rawToken string) (*accessClaims, error) {
	if s.publicKey == nil {
		return nil, errors.New("missing public key")
	}

	token, err := jwt.ParseWithClaims(rawToken, &accessClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected signing method")
		}
		return s.publicKey, nil
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

func audienceContains(audience jwt.ClaimStrings, value string) bool {
	for _, item := range audience {
		if item == value {
			return true
		}
	}
	return false
}

func scopeSet(scope string) map[string]struct{} {
	values := splitScope(scope)
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func hasScope(scopes map[string]struct{}, value string) bool {
	_, ok := scopes[value]
	return ok
}
