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

	c.JSON(http.StatusOK, gin.H{
		"sub":            claims.Subject,
		"email":          claims.Email,
		"email_verified": claims.EmailVerified,
		"name":           claims.Name,
	})
}
