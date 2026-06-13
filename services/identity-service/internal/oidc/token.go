package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

var errInvalidGrant = errors.New("invalid grant")

// token is the OAuth2 token endpoint (RFC 6749 §3.2). It authenticates the
// client (basic or post body) and dispatches by grant_type. Per-grant rate
// limiting only kicks in for refresh — auth code exchange is single-use and
// already self-limited by the code's short TTL.
// token exchanges an authorization code or refresh token for tokens.
//
// @Summary      OAuth2 Token
// @Description  Issues access/id/refresh tokens for valid authorization codes and refresh tokens.
// @Tags         oidc
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        grant_type    formData  string  true   "grant_type (authorization_code or refresh_token)"
// @Param        code          formData  string  false  "Authorization code"
// @Param        redirect_uri  formData  string  false  "Redirect URI"
// @Param        refresh_token formData  string  false  "Refresh token"
// @Success      200  {object}  object
// @Failure      400  {object}  object
// @Router       /oauth2/token [post]
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
		if !h.allowRefreshRateLimit(c, client.ClientID) {
			return
		}
		h.refreshToken(c, client)
	default:
		oauthError(c, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// exchangeAuthorizationCode redeems a one-time code (RFC 6749 §4.1.3) for an
// access/ID/refresh token bundle. PKCE verification (RFC 7636 §4.6) and the
// atomic "consumed_at IS NULL → consumed_at = now" update enforce single-use
// even under concurrent retries.
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
	if !h.service.hasActiveSession(ctx, record.UserID, record.SessionID) {
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
		if err := h.service.lockActiveSessionWithDB(ctx, tx, user.ID, record.SessionID); err != nil {
			return errInvalidGrant
		}
		result := tx.Model(&store.OAuthAuthorizationCode{}).
			Where("id = ? AND consumed_at IS NULL", record.ID).
			Update("consumed_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errInvalidGrant
		}
		if !h.service.hasActiveSessionWithDB(ctx, tx, user.ID, record.SessionID) {
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

// introspect implements RFC 7662 token introspection. It accepts either an
// access token (JWT) or a refresh token (opaque, looked up by hash) and only
// returns active=true when the token still belongs to the requesting client.
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

// revoke revokes a refresh token and its family for a given client.
//
// Call chain: POST /oauth2/revoke → revoke → revokeRefreshTokenGrant
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
	if err := h.service.revokeRefreshTokenGrant(c.Request.Context(), rawToken, client.ClientID, now); err != nil {
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}
	noContentOrJSON(c)
}

// logout implements OpenID Connect RP-Initiated Logout. When a browser hits
// this endpoint with an SSO cookie it gets a confirmation page (CSRF-protected
// POST follows); programmatic clients without the cookie call performLogout
// directly. Mismatched cookie vs query session_id is rejected to prevent CSRF
// across sessions.
func (h *Handler) logout(c *gin.Context) {
	request := logoutRequest{
		ClientID:              c.Query("client_id"),
		PostLogoutRedirectURI: c.Query("post_logout_redirect_uri"),
		SessionID:             c.Query("session_id"),
	}
	cookieSessionID := h.currentLogoutCookieSessionID(c)
	if browserRequestsDocument(c) && cookieSessionID != "" {
		if request.SessionID == "" {
			request.SessionID = cookieSessionID
		}
		if _, ok := h.resolveLogoutSession(request.SessionID, cookieSessionID); !ok {
			oauthError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		h.browserLogoutPage(c, request)
		return
	}
	if cookieSessionID != "" {
		if request.SessionID == "" {
			request.SessionID = cookieSessionID
		}
		if _, ok := h.resolveLogoutSession(request.SessionID, cookieSessionID); !ok {
			oauthError(c, http.StatusBadRequest, "invalid_request")
			return
		}
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	h.performLogout(c, request)
}

// logoutPost handles the CSRF-protected POST from the browser logout confirmation
// page, then delegates to performLogout.
//
// Call chain: POST /oauth2/logout → logoutPost → performLogout
func (h *Handler) logoutPost(c *gin.Context) {
	if !logoutCSRFValid(c) {
		c.String(http.StatusForbidden, "invalid csrf token")
		return
	}
	clearLogoutCSRFCookie(c, h.service.browserCookieSecure)
	h.performLogout(c, logoutRequest{
		ClientID:              c.PostForm("client_id"),
		PostLogoutRedirectURI: c.PostForm("post_logout_redirect_uri"),
		SessionID:             c.PostForm("session_id"),
	})
}

// performLogout revokes the resolved session, clears the SSO cookie, and
// redirects to the post-logout URI when configured.
//
// Call chain: logout / logoutPost → performLogout → revokeLoginSessionWithDB + resolvePostLogoutRedirectURI
func (h *Handler) performLogout(c *gin.Context, request logoutRequest) {
	ctx := c.Request.Context()
	sessionID, ok := h.resolveLogoutSession(request.SessionID, h.currentLogoutCookieSessionID(c))
	if !ok {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if sessionID != "" {
		now := h.service.now()
		if err := h.service.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := h.service.revokeLoginSessionWithDB(ctx, tx, sessionID, now); err != nil {
				return err
			}
			if err := tx.Model(&store.RefreshToken{}).
				Where("session_id = ? AND revoked_at IS NULL", sessionID).
				Update("revoked_at", now).Error; err != nil {
				return err
			}
			return tx.Model(&store.OAuthAuthorizationCode{}).
				Where("session_id = ? AND consumed_at IS NULL", sessionID).
				Update("consumed_at", now).Error
		}); err != nil {
			oauthError(c, http.StatusInternalServerError, "server_error")
			return
		}
	}
	session.ClearOIDCAuthorizeCookie(c, h.service.browserCookieSecure)
	clearLogoutCSRFCookie(c, h.service.browserCookieSecure)

	redirectURI, err := h.service.resolvePostLogoutRedirectURI(ctx, request.ClientID, request.PostLogoutRedirectURI)
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

// resolveLogoutSession resolves the effective session ID from the requested and
// cookie values. If both are present they must match; otherwise the cookie
// value is used as default.
func (h *Handler) resolveLogoutSession(requestedSessionID, cookieSessionID string) (string, bool) {
	requestedSessionID = strings.TrimSpace(requestedSessionID)
	cookieSessionID = strings.TrimSpace(cookieSessionID)
	if requestedSessionID != "" {
		if cookieSessionID == "" || requestedSessionID != cookieSessionID {
			return "", false
		}
		return requestedSessionID, true
	}
	return cookieSessionID, true
}

// currentLogoutCookieSessionID parses the OIDC SSO cookie and returns the session ID.
//
// Call chain: logout → currentLogoutCookieSessionID → ParseOIDCAuthorizeCookie
func (h *Handler) currentLogoutCookieSessionID(c *gin.Context) string {
	cookieValue, err := c.Cookie(session.OIDCAuthorizeCookieName)
	if err != nil || strings.TrimSpace(cookieValue) == "" {
		return ""
	}
	claims, err := session.ParseOIDCAuthorizeCookie(cookieValue, h.service.publicKey)
	if h.service.keyring != nil {
		claims, err = session.ParseOIDCAuthorizeCookieWithKeyring(cookieValue, h.service.keyring)
	}
	if err != nil {
		return ""
	}
	return strings.TrimSpace(claims.SessionID)
}

// issueTokenResponse signs access and ID tokens, and optionally creates a refresh
// token row when the client supports refresh_token grant and offline_access scope.
//
// Call chain: exchangeAuthorizationCode → issueTokenResponse → signAccessToken + signIDToken + DB Create RefreshToken
func (s *Service) issueTokenResponse(ctx context.Context, db *gorm.DB, user *store.User, client *store.OAuthClient, record *store.OAuthAuthorizationCode) (*tokenResponse, error) {
	issueRefreshToken := supportsGrantType(client, "refresh_token") && hasScope(scopeSet(record.Scope), "offline_access")
	sessionID := strings.TrimSpace(record.SessionID)
	if sessionID == "" {
		return nil, errInvalidGrant
	}

	familyID := ""
	refreshToken := ""
	if issueRefreshToken {
		var err error
		familyID, err = s.randomID(16)
		if err != nil {
			return nil, err
		}
		refreshToken, err = s.randomID(32)
		if err != nil {
			return nil, err
		}
	}

	accessToken, err := s.signAccessToken(user, client.ClientID, client.TenantID, sessionID, record.Scope)
	if err != nil {
		return nil, err
	}
	idToken, err := s.signIDToken(user, client.ClientID, record.Nonce, record.Scope)
	if err != nil {
		return nil, err
	}

	if issueRefreshToken {
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

// refreshToken rotates an OIDC refresh token in a transaction: revoke the old one,
// create a replacement in the same family, and sign new access/ID tokens.
//
// Call chain: POST /oauth2/token (refresh_token grant) → refreshToken → DB Transaction + signAccessToken + signIDToken
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
	if strings.TrimSpace(current.SessionID) == "" {
		if err := h.service.recordRefreshTokenReuse(ctx, current); err != nil {
			if isSQLiteWriteLock(err) {
				oauthError(c, http.StatusBadRequest, "invalid_grant")
				return
			}
			oauthError(c, http.StatusInternalServerError, "server_error")
			return
		}
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if current.RevokedAt != nil {
		if err := h.service.recordRefreshTokenReuse(ctx, current); err != nil {
			if isSQLiteWriteLock(err) {
				oauthError(c, http.StatusBadRequest, "invalid_grant")
				return
			}
			oauthError(c, http.StatusInternalServerError, "server_error")
			return
		}
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !h.service.validateRefreshToken(ctx, current) {
		oauthError(c, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !hasScope(scopeSet(current.Scope), "offline_access") {
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
		if err := h.service.lockActiveSessionWithDB(ctx, tx, current.UserID, current.SessionID); err != nil {
			return errInvalidGrant
		}
		result := tx.Model(&store.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", current.ID).
			Update("revoked_at", now)
		if result.Error != nil {
			if isSQLiteWriteLock(result.Error) {
				return errInvalidGrant
			}
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
			if err := h.service.recordRefreshTokenReuse(ctx, current); err != nil {
				if isSQLiteWriteLock(err) {
					oauthError(c, http.StatusBadRequest, "invalid_grant")
					return
				}
				oauthError(c, http.StatusInternalServerError, "server_error")
				return
			}
			oauthError(c, http.StatusBadRequest, "invalid_grant")
			return
		}
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}

	c.JSON(http.StatusOK, response)
}

// recordRefreshTokenReuse is the OIDC counterpart to session.rejectRefreshTokenReuse:
// detecting a replayed/revoked refresh token kills the whole family + session and
// emits an audit entry so operators can investigate compromise.
func (s *Service) recordRefreshTokenReuse(ctx context.Context, token store.RefreshToken) error {
	if err := s.revokeRefreshTokenFamily(ctx, token.FamilyID); err != nil {
		return err
	}
	if err := s.revokeLoginSession(ctx, token.SessionID); err != nil {
		return err
	}
	s.recordAuditBestEffort(ctx, audit.Entry{
		ActorUserID: token.UserID,
		TenantID:    token.TenantID,
		Action:      audit.ActionRefreshTokenReuseDetected,
		TargetType:  audit.TargetTypeTokenFamily,
		TargetID:    token.FamilyID,
		Metadata: map[string]any{
			"session_id": token.SessionID,
			"client_id":  token.ClientID,
		},
	})
	return nil
}

// revokeRefreshTokenFamily sets revoked_at on every non-revoked token in the family.
func (s *Service) revokeRefreshTokenFamily(ctx context.Context, familyID string) error {
	now := s.now()
	return s.db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).
		Update("revoked_at", now).Error
}

// revokeRefreshTokenGrant revokes a refresh token, its family, and its login
// session, then records an audit entry.
//
// Call chain: handler.revoke → revokeRefreshTokenGrant → revokeLoginSessionWithDB + DB UPDATE family
func (s *Service) revokeRefreshTokenGrant(ctx context.Context, rawToken, clientID string, now time.Time) error {
	var token store.RefreshToken
	err := s.db.WithContext(ctx).
		Where("token_hash = ? AND client_id = ?", s.hashToken(rawToken), clientID).
		First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.revokeLoginSessionWithDB(ctx, tx, token.SessionID, now); err != nil {
			return err
		}
		if err := tx.Model(&store.RefreshToken{}).
			Where("family_id = ? AND client_id = ? AND revoked_at IS NULL", token.FamilyID, clientID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	s.recordAuditBestEffort(ctx, audit.Entry{
		ActorUserID: token.UserID,
		TenantID:    token.TenantID,
		Action:      audit.ActionLogout,
		TargetType:  audit.TargetTypeTokenFamily,
		TargetID:    token.FamilyID,
		Metadata: map[string]any{
			"client_id":  clientID,
			"session_id": token.SessionID,
			"reason":     "oidc_revoke",
		},
	})
	return nil
}

// revokeLoginSession sets revoked_at on a single login session.
func (s *Service) revokeLoginSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	now := s.now()
	return s.db.WithContext(ctx).
		Model(&store.LoginSession{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", now).Error
}

// revokeLoginSessionWithDB locks and revokes a login session within a transaction.
//
// Call chain: performLogout / revokeRefreshTokenGrant → revokeLoginSessionWithDB → DB SELECT FOR UPDATE + UPDATE
func (s *Service) revokeLoginSessionWithDB(ctx context.Context, db *gorm.DB, sessionID string, now time.Time) error {
	if err := db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", sessionID).
		First(&store.LoginSession{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	return db.Model(&store.LoginSession{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", now).Error
}

// isSQLiteWriteLock detects SQLite write-lock errors so callers can treat them
// as concurrency conflicts.
func isSQLiteWriteLock(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "database table is locked") || strings.Contains(message, "database is locked")
}

// recordAuditBestEffort writes an audit entry and logs a warning on failure.
func (s *Service) recordAuditBestEffort(ctx context.Context, entry audit.Entry) {
	if err := s.audit.Record(ctx, entry); err != nil {
		slog.Warn("oidc audit record failed",
			"action", entry.Action,
			"target_type", entry.TargetType,
			"target_id", entry.TargetID,
			"error", err,
		)
	}
}

// signAccessToken signs an OIDC-scoped JWT access token with RS256.
//
// Call chain: issueTokenResponse / refreshToken → signAccessToken → jwt.SignedString
func (s *Service) signAccessToken(user *store.User, clientID string, tenantID int64, sessionID, scope string) (string, error) {
	issuedAt := s.now()
	jti, err := s.randomID(16)
	if err != nil {
		return "", err
	}
	scopes := scopeSet(scope)

	claims := accessClaims{
		Scope:        scope,
		TokenUse:     accessTokenUseOIDC,
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
		claims.Name = user.Nickname
		claims.PreferredUsername = user.Username
		claims.Username = user.Username
		claims.Nickname = user.Nickname
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.privateKey)
}

// signIDToken signs an OIDC ID token JWT with RS256.
//
// Call chain: issueTokenResponse / refreshToken → signIDToken → jwt.SignedString
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
		claims.Name = user.Nickname
		claims.PreferredUsername = user.Username
		claims.Username = user.Username
		claims.Nickname = user.Nickname
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.privateKey)
}

// verifyPKCE implements the RFC 7636 §4.6 check. "S256" hashes the verifier and
// base64url-encodes (no padding) to compare against the challenge. "plain"
// compares raw — accepted for legacy clients but discouraged.
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
