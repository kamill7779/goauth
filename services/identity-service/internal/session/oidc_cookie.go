package session

import (
	"context"
	"crypto/rsa"
	"errors"
	stdhttp "net/http"
	"strconv"
	"strings"

	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const (
	OIDCAuthorizeCookieName    = "goauth_oidc_session"
	oidcAuthorizeCookiePurpose = "oidc_authorize"
)

type OIDCAuthorizeClaims struct {
	Purpose   string `json:"purpose"`
	TenantID  int64  `json:"tid,omitempty"`
	SessionID string `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

func (s *Service) IssueOIDCAuthorizeCookie(user store.User, tenantID int64, sessionID string) (string, error) {
	if s.privateKey == nil {
		return "", errors.New("missing private key")
	}

	issuedAt := s.now()
	expiresAt := issuedAt.Add(s.OIDCAuthorizeCookieTTL())
	claims := OIDCAuthorizeClaims{
		Purpose:   oidcAuthorizeCookiePurpose,
		TenantID:  tenantID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(user.ID, 10),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.privateKey)
}

func (s *Service) IssueOIDCAuthorizeCookieBySessionID(ctx context.Context, sessionID string) (string, error) {
	var refreshToken store.RefreshToken
	if err := s.db.WithContext(ctx).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Order("id desc").
		First(&refreshToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrInvalidRefreshToken
		}
		return "", err
	}

	var user store.User
	if err := s.db.WithContext(ctx).First(&user, refreshToken.UserID).Error; err != nil {
		return "", err
	}
	return s.IssueOIDCAuthorizeCookie(user, refreshToken.TenantID, sessionID)
}

func ParseOIDCAuthorizeCookie(raw string, publicKey *rsa.PublicKey) (*OIDCAuthorizeClaims, error) {
	if publicKey == nil {
		return nil, errors.New("missing public key")
	}

	token, err := jwt.ParseWithClaims(raw, &OIDCAuthorizeClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*OIDCAuthorizeClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid oidc authorize cookie")
	}
	if claims.Purpose != oidcAuthorizeCookiePurpose || strings.TrimSpace(claims.Subject) == "" {
		return nil, errors.New("invalid oidc authorize cookie")
	}
	return claims, nil
}

func SetOIDCAuthorizeCookie(c *gin.Context, value string, maxAgeSeconds int) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(OIDCAuthorizeCookieName, value, maxAgeSeconds, "/", "", true, true)
}

func ClearOIDCAuthorizeCookie(c *gin.Context) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(OIDCAuthorizeCookieName, "", -1, "/", "", true, true)
}
