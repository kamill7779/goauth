package oidc

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
)

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
