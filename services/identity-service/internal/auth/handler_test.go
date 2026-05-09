package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
)

func TestLoginSetsOIDCAuthorizeCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	sessionService := session.NewService(service.db, config.Config{
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, privateKey)

	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	now := time.Now().UTC()
	user := store.User{
		Email:           "login@example.com",
		DisplayName:     "Login User",
		PasswordHash:    hash,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	found := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == session.OIDCAuthorizeCookieName {
			found = true
			if cookie.Value == "" {
				t.Fatal("oidc authorize cookie is empty")
			}
			if !cookie.Secure {
				t.Fatal("expected oidc authorize cookie to be secure")
			}
			if !cookie.HttpOnly {
				t.Fatal("expected oidc authorize cookie to be httpOnly")
			}
		}
	}
	if !found {
		t.Fatal("expected oidc authorize cookie to be set")
	}
}
