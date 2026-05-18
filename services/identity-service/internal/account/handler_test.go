package account

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/password"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

func TestUpdateProfileRejectsUsernameChange(t *testing.T) {
	router, db, user, token := newAccountTestRouter(t)

	recorder := patchAccountProfile(t, router, token, `{"username":"renamed-user","display_name":"Renamed"}`)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "username cannot be changed") {
		t.Fatalf("body = %s, want username immutable error", recorder.Body.String())
	}

	var stored store.User
	if err := db.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if stored.Username != user.Username {
		t.Fatalf("username = %q, want %q", stored.Username, user.Username)
	}
	if stored.DisplayName != user.DisplayName {
		t.Fatalf("display_name = %q, want unchanged %q", stored.DisplayName, user.DisplayName)
	}
}

func TestUpdateProfileAllowsLegacySameUsernamePayload(t *testing.T) {
	router, db, user, token := newAccountTestRouter(t)

	recorder := patchAccountProfile(t, router, token, `{"username":"stable-user","display_name":"Renamed"}`)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var stored store.User
	if err := db.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if stored.Username != user.Username {
		t.Fatalf("username = %q, want %q", stored.Username, user.Username)
	}
	if stored.DisplayName != "Renamed" {
		t.Fatalf("display_name = %q, want Renamed", stored.DisplayName)
	}
}

func newAccountTestRouter(t *testing.T) (*gin.Engine, *gorm.DB, store.User, string) {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	sessionService := session.NewService(db, config.Config{
		JWTKeyID:          "test-key",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   30 * 24 * time.Hour,
		BrowserSessionTTL: 12 * time.Hour,
	}, privateKey)

	verifiedAt := time.Now().UTC()
	user := store.User{
		Email:           "stable@example.com",
		Username:        "stable-user",
		Nickname:        "Stable",
		DisplayName:     "Stable User",
		Locale:          "zh-CN",
		PasswordHash:    "hash",
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &verifiedAt,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	pair, err := sessionService.IssueTokens(context.Background(), session.IssueTokensInput{
		User:     user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	router := gin.New()
	NewHandler(
		db,
		sessionService,
		session.AuthMiddleware(sessionService, &privateKey.PublicKey),
		password.Policy{MinLength: 8},
		t.TempDir(),
	).RegisterRoutes(router)

	return router, db, user, pair.AccessToken
}

func patchAccountProfile(t *testing.T, router http.Handler, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodPatch, "/v1/account/profile", bytes.NewReader([]byte(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}
