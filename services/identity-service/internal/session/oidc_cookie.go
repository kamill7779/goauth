package session

import (
	"context"
	"crypto/rsa"
	"errors"
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/jwtkey"
	"goauth/services/identity-service/internal/store"
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

// IssueOIDCAuthorizeCookie signs a short-lived JWT cookie that records the
// user's active SSO session so the OIDC authorize endpoint can skip re-login.
//
// Call chain: handler.login → IssueOIDCAuthorizeCookie → jwt.SignedString
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

// IssueOIDCAuthorizeCookieBySessionID resolves the latest refresh token for the
// session, loads the user, and issues an OIDC authorize cookie.
//
// Call chain: handler.refresh → IssueOIDCAuthorizeCookieBySessionID → IssueOIDCAuthorizeCookie
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

// ParseOIDCAuthorizeCookie verifies and decodes the OIDC authorize cookie JWT
// using a single RSA public key.
func ParseOIDCAuthorizeCookie(raw string, publicKey *rsa.PublicKey) (*OIDCAuthorizeClaims, error) {
	if publicKey == nil {
		return nil, errors.New("missing public key")
	}

	return parseOIDCAuthorizeCookie(raw, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
}

// ParseOIDCAuthorizeCookieWithKeyring verifies and decodes the cookie JWT using
// a keyring that supports key rotation.
func ParseOIDCAuthorizeCookieWithKeyring(raw string, keyring *jwtkey.Keyring) (*OIDCAuthorizeClaims, error) {
	if keyring == nil {
		return nil, errors.New("missing keyring")
	}
	return parseOIDCAuthorizeCookie(raw, keyring.Keyfunc)
}

// parseOIDCAuthorizeCookie is the shared JWT parse+validate logic for both
// single-key and keyring codepaths.
func parseOIDCAuthorizeCookie(raw string, keyfunc jwt.Keyfunc) (*OIDCAuthorizeClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &OIDCAuthorizeClaims{}, keyfunc)
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

// SetOIDCAuthorizeCookie writes the OIDC SSO cookie to the response.
func (s *Service) SetOIDCAuthorizeCookie(c *gin.Context, value string, maxAgeSeconds int) {
	SetOIDCAuthorizeCookie(c, value, maxAgeSeconds, s.browserCookieSecure)
}

// SetOIDCAuthorizeCookie writes the OIDC SSO cookie to the response with an
// explicit secure flag.
func SetOIDCAuthorizeCookie(c *gin.Context, value string, maxAgeSeconds int, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(OIDCAuthorizeCookieName, value, maxAgeSeconds, "/", "", secure, true)
}

// ClearOIDCAuthorizeCookie removes the OIDC SSO cookie from the browser.
func (s *Service) ClearOIDCAuthorizeCookie(c *gin.Context) {
	ClearOIDCAuthorizeCookie(c, s.browserCookieSecure)
}

// ClearOIDCAuthorizeCookie removes the OIDC SSO cookie from the browser with an
// explicit secure flag.
func ClearOIDCAuthorizeCookie(c *gin.Context, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(OIDCAuthorizeCookieName, "", -1, "/", "", secure, true)
}
