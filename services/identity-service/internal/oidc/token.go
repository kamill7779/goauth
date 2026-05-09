package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
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
	case "refresh_token":
		if !supportsGrantType(client, "refresh_token") {
			oauthError(c, http.StatusBadRequest, "unauthorized_client")
			return
		}
		h.refreshToken(c, client)
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
		if claims.ClientID != client.ClientID || h.service.validateAccessClaims(c.Request.Context(), *claims) != nil {
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
		First(&refreshToken).Error; err == nil && refreshToken.ClientID == client.ClientID && h.service.validateRefreshToken(c.Request.Context(), refreshToken) {
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
	requestedSessionID := strings.TrimSpace(c.Query("session_id"))
	cookieSessionID := ""
	if cookieValue, err := c.Cookie(session.OIDCAuthorizeCookieName); err == nil && strings.TrimSpace(cookieValue) != "" {
		if claims, err := session.ParseOIDCAuthorizeCookie(cookieValue, h.service.publicKey); err == nil {
			cookieSessionID = strings.TrimSpace(claims.SessionID)
		}
	}
	sessionID := cookieSessionID
	if requestedSessionID != "" {
		if cookieSessionID == "" || requestedSessionID != cookieSessionID {
			oauthError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		sessionID = requestedSessionID
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
		TokenHash:    s.hashToken(refreshToken),
		FamilyID:     familyID,
		SessionID:    sessionID,
		UserID:       user.ID,
		TenantID:     client.TenantID,
		TokenVersion: user.TokenVersion,
		ClientID:     client.ClientID,
		Scope:        record.Scope,
		ExpiresAt:    s.now().Add(s.refreshTokenTTL),
		CreatedAt:    s.now(),
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

func (h *Handler) refreshToken(c *gin.Context, client *store.OAuthClient) {
	ctx := c.Request.Context()
	rawToken := strings.TrimSpace(c.PostForm("refresh_token"))
	if rawToken == "" {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}

	var current store.RefreshToken
	if err := h.service.db.WithContext(ctx).
		Where("token_hash = ?", h.service.hashToken(rawToken)).
		First(&current).Error; err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if current.ClientID != client.ClientID {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if current.RevokedAt != nil {
		_ = h.service.revokeRefreshTokenFamily(ctx, current.FamilyID)
		_ = h.service.audit.Record(ctx, audit.Entry{
			ActorUserID: current.UserID,
			TenantID:    current.TenantID,
			Action:      audit.ActionRefreshTokenReuseDetected,
			TargetType:  audit.TargetTypeTokenFamily,
			TargetID:    current.FamilyID,
			Metadata: map[string]any{
				"session_id": current.SessionID,
				"client_id":  current.ClientID,
			},
		})
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !h.service.validateRefreshToken(ctx, current) {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}

	user, err := h.service.loadActiveUser(ctx, current.UserID)
	if err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}

	var response *tokenResponse
	err = h.service.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := h.service.now()
		result := tx.Model(&store.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", current.ID).
			Update("revoked_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errInvalidGrant
		}

		nextRefreshToken, err := h.service.randomID(32)
		if err != nil {
			return err
		}
		accessToken, err := h.service.signAccessToken(user, client.ClientID, current.TenantID, current.SessionID, current.Scope)
		if err != nil {
			return err
		}
		idToken, err := h.service.signIDToken(user, client.ClientID, "", current.Scope)
		if err != nil {
			return err
		}

		replacement := store.RefreshToken{
			TokenHash:    h.service.hashToken(nextRefreshToken),
			FamilyID:     current.FamilyID,
			SessionID:    current.SessionID,
			UserID:       current.UserID,
			TenantID:     current.TenantID,
			TokenVersion: user.TokenVersion,
			ClientID:     current.ClientID,
			Scope:        current.Scope,
			ExpiresAt:    h.service.now().Add(h.service.refreshTokenTTL),
			CreatedAt:    h.service.now(),
		}
		if err := tx.WithContext(ctx).Create(&replacement).Error; err != nil {
			return err
		}
		if err := tx.Model(&store.RefreshToken{}).
			Where("id = ?", current.ID).
			Update("replaced_by_token_id", replacement.ID).Error; err != nil {
			return err
		}

		response = &tokenResponse{
			AccessToken:  accessToken,
			IDToken:      idToken,
			RefreshToken: nextRefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int64(h.service.accessTokenTTL.Seconds()),
			Scope:        current.Scope,
		}
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

func (s *Service) revokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	now := s.now()
	return s.db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", now).Error
}

func (s *Service) signAccessToken(user *store.User, clientID string, tenantID int64, sessionID, scope string) (string, error) {
	issuedAt := s.now()
	jti, err := s.randomID(16)
	if err != nil {
		return "", err
	}
	scopes := scopeSet(scope)

	claims := accessClaims{
		Scope:        scope,
		ClientID:     clientID,
		TenantID:     tenantID,
		SessionID:    sessionID,
		TokenVersion: user.TokenVersion,
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
