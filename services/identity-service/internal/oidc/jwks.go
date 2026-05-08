package oidc

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
)

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
