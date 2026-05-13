// Package middleware provides HTTP middleware for the Gin router: structured
// logging, request ID propagation, and other cross-cutting concerns.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/gin-gonic/gin"
)

const RequestIDHeader = "X-Request-ID"
const RequestIDKey = "request_id"

// RequestID generates or propagates a request ID for each incoming request.
// The ID is stored in the Gin context and written to the X-Request-ID response header.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.GetHeader(RequestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		c.Set(RequestIDKey, id)
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Format as UUID v4 (simplified hex without dashes for brevity).
	return hex.EncodeToString(b)
}
