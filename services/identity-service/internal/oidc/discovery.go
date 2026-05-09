package oidc

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) discovery(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                h.service.issuer,
		"authorization_endpoint":                h.service.issuer + "/oauth2/authorize",
		"token_endpoint":                        h.service.issuer + "/oauth2/token",
		"userinfo_endpoint":                     h.service.issuer + "/oauth2/userinfo",
		"jwks_uri":                              h.service.issuer + "/oauth2/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	})
}
