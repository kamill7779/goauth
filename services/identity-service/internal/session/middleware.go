package session

import (
	"crypto/rsa"
	"errors"
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/jwtkey"
)

const contextClaimsKey = "session_claims"

// AuthMiddleware validates an `Authorization: Bearer <jwt>` header in two
// stages: cryptographic verification against publicKey, then live state checks
// (user active, session not revoked, token version current) so that logout and
// account disable take effect without waiting for token expiry.
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
			// Explicitly pin RS256: rejecting other algorithms blocks the classic
			// "alg=none" and HS256-with-public-key confusion attacks.
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

func AuthMiddlewareWithKeyring(service *Service, keyring *jwtkey.Keyring) gin.HandlerFunc {
	return func(c *gin.Context) {
		if service == nil || keyring == nil {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid auth configuration"})
			return
		}

		header := c.GetHeader("Authorization")
		tokenString, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || strings.TrimSpace(tokenString) == "" {
			c.AbortWithStatusJSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}

		token, err := jwt.ParseWithClaims(strings.TrimSpace(tokenString), &accessClaims{}, keyring.Keyfunc)
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
