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
func (h *Handler) jwks(c *gin.Context) {
	if h.service.publicKey == nil {
		c.JSON(http.StatusOK, gin.H{"keys": []any{}})
		return
	}

	n := base64.RawURLEncoding.EncodeToString(h.service.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.service.publicKey.E)).Bytes())
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": h.service.keyID,
				"n":   n,
				"e":   e,
			},
		},
	})
}
