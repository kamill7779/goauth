package oidc

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
)

// discovery serves the OIDC Discovery document (RFC 8414).
//
// Call chain: GET /.well-known/openid-configuration → discovery → static config JSON
//
// @Summary      OIDC Discovery
// @Description  Returns the OpenID Connect discovery document.
// @Tags         oidc
// @Produce      json
// @Success      200  {object}  object
// @Router       /.well-known/openid-configuration [get]
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

// jwks publishes our signing public key in JWK Set form (RFC 7517) so RPs and
// API gateways can verify our access/ID tokens without a shared secret. The
// modulus and exponent are base64url-encoded big-endian per RFC 7518 §6.3.1.
// jwks returns the JSON Web Key Set for token verification.
//
// Call chain: GET /oauth2/jwks → jwks → jwksPublicKeys → JSON response
//
// @Summary      JWKS
// @Description  Returns the public keys used to verify token signatures.
// @Tags         oidc
// @Produce      json
// @Success      200  {object}  object
// @Router       /oauth2/jwks [get]
func (h *Handler) jwks(c *gin.Context) {
	keys := h.service.jwksPublicKeys()
	if len(keys) == 0 {
		c.JSON(http.StatusOK, gin.H{"keys": []any{}})
		return
	}

	items := make([]gin.H, 0, len(keys))
	for _, key := range keys {
		n := base64.RawURLEncoding.EncodeToString(key.Key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.Key.E)).Bytes())
		items = append(items, gin.H{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": key.ID,
			"n":   n,
			"e":   e,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"keys": items,
	})
}
