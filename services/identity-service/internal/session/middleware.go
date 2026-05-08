package session

import (
	"crypto/rsa"
	"errors"
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const contextClaimsKey = "session_claims"

func AuthMiddleware(service *Service, publicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		if service == nil || publicKey == nil {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid auth configuration"})
			return
		}

		header := c.GetHeader("Authorization")
		tokenString, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || strings.TrimSpace(tokenString) == "" {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		token, err := jwt.ParseWithClaims(strings.TrimSpace(tokenString), &accessClaims{}, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodRS256 {
				return nil, errors.New("unexpected signing method")
			}
			return publicKey, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		claims, ok := token.Claims.(*accessClaims)
		if !ok || !token.Valid {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if err := service.validateAccessClaims(c.Request.Context(), *claims); err != nil {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set(contextClaimsKey, *claims)
		c.Next()
	}
}

func SystemUserMiddleware(service *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if service == nil {
			c.AbortWithStatusJSON(stdhttp.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
			return
		}

		userID, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		ok, err = service.isSystemUser(c.Request.Context(), userID)
		if err != nil {
			c.AbortWithStatusJSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(stdhttp.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Next()
	}
}

func ClaimsFromContext(c *gin.Context) (accessClaims, bool) {
	value, ok := c.Get(contextClaimsKey)
	if !ok {
		return accessClaims{}, false
	}

	claims, ok := value.(accessClaims)
	if !ok {
		return accessClaims{}, false
	}
	return claims, true
}
