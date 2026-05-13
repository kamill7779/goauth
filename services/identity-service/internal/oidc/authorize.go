package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

func (h *Handler) authorize(c *gin.Context) {
	ctx := c.Request.Context()
	clientID := strings.TrimSpace(c.Query("client_id"))
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))
	if !h.allowAuthorizeRateLimit(c, clientID) {
		return
	}

	client, err := h.service.loadClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			oauthError(c, http.StatusBadRequest, "invalid_client")
			return
		}
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}

	if c.Query("response_type") != "code" {
		oauthError(c, http.StatusBadRequest, "unsupported_response_type")
		return
	}
	if client.Status != store.UserStatusActive || !supportsGrantType(client, "authorization_code") {
		oauthError(c, http.StatusBadRequest, "unauthorized_client")
		return
	}
	if redirectURI == "" || !h.service.validateRedirectURI(client, redirectURI) {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.service.validateScope(client, c.Query("scope")); err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_scope")
		return
	}

	codeChallenge := strings.TrimSpace(c.Query("code_challenge"))
	codeChallengeMethod := strings.ToUpper(strings.TrimSpace(c.DefaultQuery("code_challenge_method", "plain")))
	if codeChallenge == "" || (codeChallengeMethod != "PLAIN" && codeChallengeMethod != "S256") {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}

	cookieValue, err := c.Cookie(session.OIDCAuthorizeCookieName)
	if err != nil || strings.TrimSpace(cookieValue) == "" {
		if h.redirectBrowserToLogin(c) {
			return
		}
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}

	sessionClaims, err := session.ParseOIDCAuthorizeCookie(cookieValue, h.service.publicKey)
	if err != nil {
		if h.redirectBrowserToLogin(c) {
			return
		}
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(sessionClaims.Subject), 10, 64)
	if err != nil || userID == 0 {
		if h.redirectBrowserToLogin(c) {
			return
		}
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}
	if !h.service.hasActiveSession(ctx, userID, sessionClaims.SessionID) {
		if h.redirectBrowserToLogin(c) {
			return
		}
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}
	membershipOK, err := h.service.ensureClientTenantMembership(ctx, userID, client)
	if err != nil {
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}
	if !membershipOK {
		oauthError(c, http.StatusForbidden, "access_denied")
		return
	}
	user, err := h.service.loadUser(ctx, userID)
	if err != nil || user.Status != store.UserStatusActive {
		if h.redirectBrowserToLogin(c) {
			return
		}
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}

	rawCode, err := h.service.randomID(32)
	if err != nil {
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}

	// Only the hashed code is stored so leaking the database does not expose reusable auth codes.
	record := store.OAuthAuthorizationCode{
		CodeHash:            h.service.hashAuthorizationCode(rawCode),
		ClientID:            client.ClientID,
		UserID:              user.ID,
		TenantID:            client.TenantID,
		RedirectURI:         redirectURI,
		Scope:               strings.Join(splitScope(c.Query("scope")), " "),
		SessionID:           strings.TrimSpace(sessionClaims.SessionID),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               strings.TrimSpace(c.Query("nonce")),
		ExpiresAt:           h.service.now().Add(h.service.authorizationCodeTTL),
		CreatedAt:           h.service.now(),
	}
	if err := h.service.db.WithContext(ctx).Create(&record).Error; err != nil {
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		oauthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	query := redirectURL.Query()
	query.Set("code", rawCode)
	if state := strings.TrimSpace(c.Query("state")); state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()
	c.Redirect(http.StatusFound, redirectURL.String())
}

func (h *Handler) redirectBrowserToLogin(c *gin.Context) bool {
	if h.service.browserLoginURL == "" || !browserPrefersHTML(c) {
		return false
	}

	returnTo, ok := buildAuthorizeReturnTarget(h.service.issuer, c.Request.URL.RequestURI())
	if !ok {
		return false
	}

	c.Redirect(http.StatusFound, buildBrowserLoginRedirectURL(h.service.browserLoginURL, returnTo))
	return true
}
