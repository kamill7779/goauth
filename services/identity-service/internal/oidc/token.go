package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"example.com/identity-service/internal/session"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

var errInvalidGrant = errors.New("invalid grant")

func (h *Handler) token(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}

	client, err := h.service.authenticateClientFromRequest(c)
	if err != nil {
		oauthError(c, http.StatusUnauthorized, "invalid_client")
		return
	}

	switch c.PostForm("grant_type") {
	case "authorization_code":
		if !supportsGrantType(client, "authorization_code") {
			oauthError(c, http.StatusBadRequest, "unauthorized_client")
			return
		}
		h.exchangeAuthorizationCode(c, client)
	default:
		oauthError(c, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (h *Handler) exchangeAuthorizationCode(c *gin.Context, client *store.OAuthClient) {
	ctx := c.Request.Context()
	code := strings.TrimSpace(c.PostForm("code"))
	redirectURI := strings.TrimSpace(c.PostForm("redirect_uri"))
	codeVerifier := c.PostForm("code_verifier")

	var record store.OAuthAuthorizationCode
	if err := h.service.db.WithContext(ctx).
		Where("code_hash = ?", h.service.hashAuthorizationCode(code)).
		First(&record).Error; err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}

	if record.ClientID != client.ClientID || record.RedirectURI != redirectURI {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if record.TenantID != client.TenantID {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if record.ConsumedAt != nil || record.ExpiresAt.Before(h.service.now()) {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !verifyPKCE(codeVerifier, record.CodeChallenge, record.CodeChallengeMethod) {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}

	user, err := h.service.loadUser(ctx, record.UserID)
	if err != nil || user.Status != store.UserStatusActive {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !h.service.hasActiveTenantMembership(ctx, user.ID, client.TenantID) {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}

	var response *tokenResponse
	err = h.service.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := h.service.now()
		result := tx.Model(&store.OAuthAuthorizationCode{}).
			Where("id = ? AND consumed_at IS NULL", record.ID).
			Update("consumed_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errInvalidGrant
		}

		nextResponse, err := h.service.issueTokenResponse(ctx, tx, user, client, &record)
		if err != nil {
			return err
		}
		response = nextResponse
		return nil
	})
	if err != nil {
		if errors.Is(err, errInvalidGrant) {
			oauthError(c, http.StatusBadRequest, "invalid_grant")
			return
		}
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) introspect(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	client, err := h.service.authenticateClientFromRequest(c)
	if err != nil {
		oauthError(c, http.StatusUnauthorized, "invalid_client")
		return
	}

	rawToken := strings.TrimSpace(c.PostForm("token"))
	if rawToken == "" {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}

	if claims, err := h.service.parseAccessToken(rawToken); err == nil {
		if claims.ClientID != client.ClientID {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		exp := int64(0)
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Unix()
		}
		c.JSON(http.StatusOK, gin.H{
			"active":     true,
			"sub":        claims.Subject,
			"client_id":  claims.ClientID,
			"scope":      claims.Scope,
			"exp":        exp,
			"token_type": "Bearer",
		})
		return
	}

	var refreshToken store.RefreshToken
	if err := h.service.db.WithContext(c.Request.Context()).
		Where("token_hash = ?", h.service.hashToken(rawToken)).
		First(&refreshToken).Error; err == nil && refreshToken.ClientID == client.ClientID && refreshToken.RevokedAt == nil && refreshToken.ExpiresAt.After(h.service.now()) {
		c.JSON(http.StatusOK, gin.H{
			"active":     true,
			"sub":        strconv.FormatInt(refreshToken.UserID, 10),
			"client_id":  refreshToken.ClientID,
			"exp":        refreshToken.ExpiresAt.Unix(),
			"token_type": "refresh_token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"active": false})
}

func (h *Handler) revoke(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	client, err := h.service.authenticateClientFromRequest(c)
	if err != nil {
		oauthError(c, http.StatusUnauthorized, "invalid_client")
		return
	}

	rawToken := strings.TrimSpace(c.PostForm("token"))
	if rawToken == "" {
		noContentOrJSON(c)
		return
	}

	now := h.service.now()
	_ = h.service.db.WithContext(c.Request.Context()).
		Model(&store.RefreshToken{}).
		Where("token_hash = ? AND client_id = ? AND revoked_at IS NULL", h.service.hashToken(rawToken), client.ClientID).
		Update("revoked_at", now).Error
	noContentOrJSON(c)
}

func (h *Handler) logout(c *gin.Context) {
	ctx := c.Request.Context()
	sessionID := strings.TrimSpace(c.Query("session_id"))
	if sessionID == "" {
		if cookieValue, err := c.Cookie(session.OIDCAuthorizeCookieName); err == nil && strings.TrimSpace(cookieValue) != "" {
			if claims, err := session.ParseOIDCAuthorizeCookie(cookieValue, h.service.publicKey); err == nil {
				sessionID = strings.TrimSpace(claims.SessionID)
			}
		}
	}
	if sessionID != "" {
		now := h.service.now()
		_ = h.service.db.WithContext(ctx).
			Model(&store.RefreshToken{}).
			Where("session_id = ? AND revoked_at IS NULL", sessionID).
			Update("revoked_at", now).Error
	}
	session.ClearOIDCAuthorizeCookie(c)

	redirectURI, err := h.service.resolvePostLogoutRedirectURI(ctx, c.Query("client_id"), c.Query("post_logout_redirect_uri"))
	if err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if redirectURI != "" {
		c.Redirect(http.StatusFound, redirectURI)
		return
	}
	c.JSON(http.StatusOK, gin.H{"logout": true})
}

func (s *Service) issueTokenResponse(ctx context.Context, db *gorm.DB, user *store.User, client *store.OAuthClient, record *store.OAuthAuthorizationCode) (*tokenResponse, error) {
	sessionID, err := s.randomID(16)
	if err != nil {
		return nil, err
	}
	familyID, err := s.randomID(16)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.randomID(32)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.signAccessToken(user, client.ClientID, client.TenantID, sessionID, record.Scope)
	if err != nil {
		return nil, err
	}
	idToken, err := s.signIDToken(user, client.ClientID, record.Nonce, record.Scope)
	if err != nil {
		return nil, err
	}

	refreshRecord := store.RefreshToken{
		TokenHash: s.hashToken(refreshToken),
		FamilyID:  familyID,
		SessionID: sessionID,
		UserID:    user.ID,
		TenantID:  client.TenantID,
		ClientID:  client.ClientID,
		ExpiresAt: s.now().Add(s.refreshTokenTTL),
		CreatedAt: s.now(),
	}
	if err := db.WithContext(ctx).Create(&refreshRecord).Error; err != nil {
		return nil, err
	}

	return &tokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
		Scope:        record.Scope,
	}, nil
}

func (s *Service) signAccessToken(user *store.User, clientID string, tenantID int64, sessionID, scope string) (string, error) {
	issuedAt := s.now()
	jti, err := s.randomID(16)
	if err != nil {
		return "", err
	}
	scopes := scopeSet(scope)

	claims := accessClaims{
		Scope:     scope,
		ClientID:  clientID,
		TenantID:  tenantID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   strconv.FormatInt(user.ID, 10),
			Audience:  []string{clientID},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(s.accessTokenTTL)),
			ID:        jti,
		},
	}
	if hasScope(scopes, "email") {
		claims.Email = user.Email
		claims.EmailVerified = user.EmailVerifiedAt != nil
	}
	if hasScope(scopes, "profile") {
		claims.Name = user.DisplayName
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.privateKey)
}

func (s *Service) signIDToken(user *store.User, clientID, nonce, scope string) (string, error) {
	issuedAt := s.now()
	scopes := scopeSet(scope)
	claims := idTokenClaims{
		Nonce: nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   strconv.FormatInt(user.ID, 10),
			Audience:  []string{clientID},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(s.accessTokenTTL)),
		},
	}
	if hasScope(scopes, "email") {
		claims.Email = user.Email
		claims.EmailVerified = user.EmailVerifiedAt != nil
	}
	if hasScope(scopes, "profile") {
		claims.Name = user.DisplayName
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.privateKey)
}

func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}

	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
	case "", "PLAIN":
		return verifier == challenge
	default:
		return false
	}
}
