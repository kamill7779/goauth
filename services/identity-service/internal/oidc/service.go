package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const (
	defaultAuthorizationCodeTTL = 10 * time.Minute
	defaultAccessTokenTTL       = 15 * time.Minute
	defaultRefreshTokenTTL      = 30 * 24 * time.Hour
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
	now                  func() time.Time
}

type Handler struct {
	service *Service
}

type accessClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Scope         string `json:"scope,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	TenantID      int64  `json:"tid,omitempty"`
	SessionID     string `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

type idTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
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
		now:                  time.Now,
	}
	if privateKey != nil {
		service.publicKey = &privateKey.PublicKey
	}
	return service
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

func (s *Service) parseAccessToken(rawToken string) (*accessClaims, error) {
	if s.publicKey == nil {
		return nil, errors.New("missing public key")
	}

	token, err := jwt.ParseWithClaims(rawToken, &accessClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected signing method")
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
