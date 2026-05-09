package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/rbac"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
	"gorm.io/gorm"
)

func TestProtectedRoutesRejectAnonymous(t *testing.T) {
	router, _, _, _, _ := newIntegrationRouter(t)

	cases := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{name: "admin users", method: http.MethodGet, target: "/v1/admin/users"},
		{name: "admin oauth clients", method: http.MethodGet, target: "/v1/admin/oauth-clients"},
		{name: "authz check", method: http.MethodPost, target: "/v1/authz/check", body: `{"user_id":1,"tenant_id":1,"permission":"project:read"}`},
		{name: "my permissions", method: http.MethodGet, target: "/v1/tenants/1/my-permissions?user_id=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
			}
		})
	}
}

func TestAdminAndAuthzRoutesRejectNonSystemUser(t *testing.T) {
	router, _, sessionService, regularUser, _ := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	cases := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{name: "admin users", method: http.MethodGet, target: "/v1/admin/users"},
		{name: "admin oauth clients", method: http.MethodGet, target: "/v1/admin/oauth-clients"},
		{name: "authz check", method: http.MethodPost, target: "/v1/authz/check", body: `{"user_id":1,"tenant_id":1,"permission":"project:read"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
		})
	}
}

func TestAdminRoutesRejectRootEmailAliasWithoutSystemRole(t *testing.T) {
	router, db, sessionService, _, _ := newIntegrationRouter(t)
	rootAlias := &store.User{
		Email:        "root@tenant.test",
		DisplayName:  "root alias",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(rootAlias).Error; err != nil {
		t.Fatalf("db.Create(rootAlias) error = %v", err)
	}
	pair := issueIntegrationTokens(t, sessionService, *rootAlias, 0)

	request := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

func TestMyPermissionsUsesAuthenticatedUserInsteadOfQueryOverride(t *testing.T) {
	router, db, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	tenantID := seedTenantPermission(t, db, regularUser.ID)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, tenantID)

	request := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantIDString(tenantID)+"/my-permissions?user_id="+userIDString(otherUser.ID), nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "project:read") {
		t.Fatalf("body = %s, want own permissions", recorder.Body.String())
	}
}

func TestLogoutAllRejectsTargetingAnotherUser(t *testing.T) {
	router, db, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	ownPair := issueIntegrationTokens(t, sessionService, *regularUser, 0)
	otherPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)

	body := `{"user_id":` + userIDString(otherUser.ID) + `}`
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+ownPair.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}

	assertSessionStillActive(t, db, otherPair.SessionID)
}

func TestReadyzChecksDBAndRedisClients(t *testing.T) {
	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	mini := miniredis.RunT(t)
	cfg := config.Config{
		RedisURL:        "redis://" + mini.Addr() + "/0",
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
	redisClient, err := cache.OpenRedis(cfg)
	if err != nil {
		t.Fatalf("cache.OpenRedis() error = %v", err)
	}
	defer func() {
		if err := redisClient.Close(); err != nil {
			t.Fatalf("redisClient.Close() error = %v", err)
		}
	}()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	router := buildRouter(cfg, db, redisClient, privateKey)
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func newIntegrationRouter(t *testing.T) (*gin.Engine, *gorm.DB, *session.Service, *store.User, *store.User) {
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

	cfg := config.Config{
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
	router := buildRouter(cfg, db, nil, privateKey)
	sessionService := session.NewService(db, cfg, privateKey)

	regularUser := &store.User{
		Email:        "member@example.com",
		DisplayName:  "member",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(regularUser).Error; err != nil {
		t.Fatalf("db.Create(regularUser) error = %v", err)
	}

	otherUser := &store.User{
		Email:        "other@example.com",
		DisplayName:  "other",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(otherUser).Error; err != nil {
		t.Fatalf("db.Create(otherUser) error = %v", err)
	}

	return router, db, sessionService, regularUser, otherUser
}

func seedTenantPermission(t *testing.T, db *gorm.DB, userID int64) int64 {
	t.Helper()

	rbacService := rbac.NewService(db, nil)
	tenantService := tenant.NewService(db, rbacService)
	tenantRecord, err := tenantService.CreateTenant(t.Context(), tenant.CreateTenantInput{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("CreateTenant() error = %v", err)
	}
	member, err := tenantService.AddMember(t.Context(), tenant.AddMemberInput{
		TenantID: tenantRecord.ID,
		UserID:   userID,
		Status:   store.MemberStatusActive,
	})
	if err != nil {
		t.Fatalf("AddMember() error = %v", err)
	}
	role, err := tenantService.CreateRole(t.Context(), tenant.CreateRoleInput{
		TenantID: tenantRecord.ID,
		Name:     "Reader",
		Code:     "reader",
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	permission := store.Permission{
		Resource: "project",
		Action:   "read",
		Code:     "project:read",
	}
	if err := db.Create(&permission).Error; err != nil {
		t.Fatalf("db.Create(permission) error = %v", err)
	}
	if err := tenantService.GrantPermissions(t.Context(), role.ID, []int64{permission.ID}); err != nil {
		t.Fatalf("GrantPermissions() error = %v", err)
	}
	if err := tenantService.AssignRoles(t.Context(), member.ID, []int64{role.ID}); err != nil {
		t.Fatalf("AssignRoles() error = %v", err)
	}

	return tenantRecord.ID
}

func issueIntegrationTokens(t *testing.T, service *session.Service, user store.User, tenantID int64) *session.TokenPair {
	t.Helper()

	pair, err := service.IssueTokens(t.Context(), session.IssueTokensInput{
		User:     user,
		TenantID: tenantID,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}
	return pair
}

func assertSessionStillActive(t *testing.T, db *gorm.DB, sessionID string) {
	t.Helper()

	var count int64
	if err := db.Model(&store.RefreshToken{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Count(&count).Error; err != nil {
		t.Fatalf("count active session tokens: %v", err)
	}
	if count == 0 {
		t.Fatalf("session %s was unexpectedly revoked", sessionID)
	}
}

func tenantIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}

func userIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}
