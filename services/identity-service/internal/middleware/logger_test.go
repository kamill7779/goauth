package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestStructuredLogger_DoesNotLogQueryString(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	router := gin.New()
	router.Use(RequestID(), StructuredLogger())
	router.GET("/callback", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/callback?token=secret&code=oauth-code", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	logged := buf.String()
	if strings.Contains(logged, "token=secret") || strings.Contains(logged, "code=oauth-code") {
		t.Fatalf("log output leaked query string: %s", logged)
	}
	if !strings.Contains(logged, `"path":"/callback"`) {
		t.Fatalf("expected sanitized path in log output, got: %s", logged)
	}
}
