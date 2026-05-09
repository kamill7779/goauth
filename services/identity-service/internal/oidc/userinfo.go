package oidc

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *Handler) userInfo(c *gin.Context) {
	header := strings.TrimSpace(c.GetHeader("Authorization"))
	rawToken, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || strings.TrimSpace(rawToken) == "" {
		oauthError(c, http.StatusUnauthorized, "invalid_token")
		return
	}

	claims, err := h.service.parseAccessToken(strings.TrimSpace(rawToken))
	if err != nil {
		oauthError(c, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err := h.service.validateAccessClaims(c.Request.Context(), *claims); err != nil {
		oauthError(c, http.StatusUnauthorized, "invalid_token")
		return
	}
	scopes := scopeSet(claims.Scope)
	if strings.TrimSpace(claims.ClientID) == "" || !hasScope(scopes, "openid") {
		oauthError(c, http.StatusUnauthorized, "invalid_token")
		return
	}

	response := gin.H{
		"sub": claims.Subject,
	}
	if hasScope(scopes, "email") {
		response["email"] = claims.Email
		response["email_verified"] = claims.EmailVerified
	}
	if hasScope(scopes, "profile") {
		response["name"] = claims.Name
	}
	c.JSON(http.StatusOK, response)
}
