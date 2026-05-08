package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"example.com/identity-service/internal/session"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func (h *Handler) authorize(c *gin.Context) {
	ctx := c.Request.Context()
	clientID := strings.TrimSpace(c.Query("client_id"))
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))

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
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}

	sessionClaims, err := session.ParseOIDCAuthorizeCookie(cookieValue, h.service.publicKey)
	if err != nil {
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(sessionClaims.Subject), 10, 64)
	if err != nil || userID == 0 {
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}
	user, err := h.service.loadUser(ctx, userID)
	if err != nil || user.Status != store.UserStatusActive {
		oauthError(c, http.StatusUnauthorized, "login_required")
		return
	}

	rawCode, err := h.service.randomID(32)
	if err != nil {
		oauthError(c, http.StatusInternalServerError, "server_error")
		return
	}

	record := store.OAuthAuthorizationCode{
		CodeHash:            h.service.hashAuthorizationCode(rawCode),
		ClientID:            client.ClientID,
		UserID:              user.ID,
		TenantID:            client.TenantID,
		RedirectURI:         redirectURI,
		Scope:               strings.Join(splitScope(c.Query("scope")), " "),
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
