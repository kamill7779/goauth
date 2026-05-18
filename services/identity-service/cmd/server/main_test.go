package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/idp"
	"goauth/services/identity-service/internal/oidc"
	"goauth/services/identity-service/internal/rbac"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
	"goauth/services/identity-service/internal/user"
	"gorm.io/datatypes"
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
		{name: "account center", method: http.MethodGet, target: "/v1/account/me"},
		{name: "account 2fa status", method: http.MethodGet, target: "/v1/account/2fa/status"},
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

func TestRequireRedisFailsWhenUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	if _, err := requireRedis(config.Config{RedisURL: "redis://" + addr + "/0"}); err == nil {
		t.Fatal("requireRedis() error = nil, want failure when redis is unavailable")
	}
}

func TestRequireRedisFailsWhenGitHubLoginConfigured(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	_, err = requireRedis(config.Config{
		RedisURL:           "redis://" + addr + "/0",
		GitHubOAuthEnabled: true,
		GitHubClientID:     "client-id",
		GitHubClientSecret: "client-secret",
		GitHubRedirectURI:  "https://auth.example.com/v1/external/github/callback",
	})
	if err == nil {
		t.Fatal("requireRedis() error = nil, want error when GitHub browser login needs exchange store")
	}
}

func TestFrontendCallbackURLFromBrowserLoginURL(t *testing.T) {
	cases := []struct {
		name            string
		browserLoginURL string
		want            string
	}{
		{name: "same origin path", browserLoginURL: "/login", want: "/external/callback"},
		{name: "absolute frontend url", browserLoginURL: "https://console.example.com/login", want: "https://console.example.com/external/callback"},
		{name: "nested frontend path", browserLoginURL: "https://console.example.com/auth/login", want: "https://console.example.com/external/callback"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := frontendCallbackURLFromBrowserLoginURL(tc.browserLoginURL); got != tc.want {
				t.Fatalf("frontendCallbackURLFromBrowserLoginURL(%q) = %q, want %q", tc.browserLoginURL, got, tc.want)
			}
		})
	}
}

func TestAdminConsoleSupplementalRoutes(t *testing.T) {
	router, db, sessionService, adminUser, otherUser := newIntegrationRouter(t)
	makeSystemUser(t, db, adminUser.ID)
	pair := issueIntegrationTokens(t, sessionService, *adminUser, 0)
	otherPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)

	permissionBody := `{"resource":"file","action":"read","code":"file:read","description":"Read files"}`
	permissionRecorder := performJSON(t, router, http.MethodPost, "/v1/admin/permissions", permissionBody, pair.AccessToken)
	if permissionRecorder.Code != http.StatusCreated {
		t.Fatalf("create permission status = %d, want %d body=%s", permissionRecorder.Code, http.StatusCreated, permissionRecorder.Body.String())
	}

	cases := []struct {
		name     string
		method   string
		target   string
		body     string
		wantCode int
		wantBody string
	}{
		{name: "dashboard", method: http.MethodGet, target: "/v1/admin/dashboard", wantCode: http.StatusOK, wantBody: "total_users"},
		{name: "permissions", method: http.MethodGet, target: "/v1/admin/permissions", wantCode: http.StatusOK, wantBody: "file:read"},
		{name: "user sessions", method: http.MethodGet, target: "/v1/admin/users/" + userIDString(otherUser.ID) + "/sessions", wantCode: http.StatusOK, wantBody: otherPair.SessionID},
		{name: "audit logs", method: http.MethodGet, target: "/v1/admin/audit-logs", wantCode: http.StatusOK, wantBody: "audit_logs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := performJSON(t, router, tc.method, tc.target, tc.body, pair.AccessToken)
			if recorder.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, tc.wantCode, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.wantBody) {
				t.Fatalf("body = %s, want %q", recorder.Body.String(), tc.wantBody)
			}
		})
	}

	logoutRecorder := performJSON(t, router, http.MethodPost, "/v1/admin/users/"+userIDString(otherUser.ID)+"/logout-all", `{}`, pair.AccessToken)
	if logoutRecorder.Code != http.StatusOK {
		t.Fatalf("logout-all status = %d, want %d body=%s", logoutRecorder.Code, http.StatusOK, logoutRecorder.Body.String())
	}
	assertSessionRevoked(t, db, otherPair.SessionID)
}

func TestAdminGlobalSessionsListAndSingleRevoke(t *testing.T) {
	router, db, sessionService, adminUser, otherUser := newIntegrationRouter(t)
	makeSystemUser(t, db, adminUser.ID)
	adminPair := issueIntegrationTokens(t, sessionService, *adminUser, 0)
	otherPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)

	list := performJSON(t, router, http.MethodGet, "/v1/admin/sessions?page=1&page_size=20", "", adminPair.AccessToken)
	if list.Code != http.StatusOK {
		t.Fatalf("sessions status = %d, want %d body=%s", list.Code, http.StatusOK, list.Body.String())
	}
	listData := decodeData(t, list)
	sessions := asSlice(t, listData["sessions"], "sessions")
	if len(sessions) < 2 {
		t.Fatalf("sessions length = %d, want at least 2 body=%s", len(sessions), list.Body.String())
	}
	if total := numberFromAny(listData["total"]); total < 2 {
		t.Fatalf("sessions total = %d, want at least 2 body=%s", total, list.Body.String())
	}
	otherSession := findItemByStringField(t, sessions, "id", otherPair.SessionID)
	if got := numberFromAny(otherSession["user_id"]); got != int(otherUser.ID) {
		t.Fatalf("session user_id = %d, want %d", got, otherUser.ID)
	}
	if got := stringFromAny(otherSession["user"]); got != otherUser.Email {
		t.Fatalf("session user = %q, want %q", got, otherUser.Email)
	}
	if got := stringFromAny(otherSession["client"]); got != "web-client" {
		t.Fatalf("session client = %q, want web-client", got)
	}
	if got := stringFromAny(otherSession["status"]); got != "active" {
		t.Fatalf("session status = %q, want active", got)
	}

	search := performJSON(t, router, http.MethodGet, "/v1/admin/sessions?search=other&page=1&page_size=20", "", adminPair.AccessToken)
	if search.Code != http.StatusOK {
		t.Fatalf("search sessions status = %d, want %d body=%s", search.Code, http.StatusOK, search.Body.String())
	}
	searchItems := asSlice(t, decodeData(t, search)["sessions"], "sessions")
	if len(searchItems) != 1 {
		t.Fatalf("search sessions length = %d, want 1 body=%s", len(searchItems), search.Body.String())
	}
	if got := stringFromAny(asMap(t, searchItems[0], "sessions[0]")["id"]); got != otherPair.SessionID {
		t.Fatalf("search session id = %q, want %q", got, otherPair.SessionID)
	}

	revoke := performJSON(t, router, http.MethodPost, "/v1/admin/sessions/"+otherPair.SessionID+"/revoke", `{}`, adminPair.AccessToken)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke session status = %d, want %d body=%s", revoke.Code, http.StatusOK, revoke.Body.String())
	}
	assertSessionRevoked(t, db, otherPair.SessionID)
	assertSessionStillActive(t, db, adminPair.SessionID)
	revokedAccess := performJSON(t, router, http.MethodGet, "/v1/auth/me", "", otherPair.AccessToken)
	if revokedAccess.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session access status = %d, want %d body=%s", revokedAccess.Code, http.StatusUnauthorized, revokedAccess.Body.String())
	}
	revokedRefresh := performJSON(t, router, http.MethodPost, "/v1/auth/refresh", `{"refresh_token":"`+otherPair.RefreshToken+`"}`, "")
	if revokedRefresh.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session refresh status = %d, want %d body=%s", revokedRefresh.Code, http.StatusUnauthorized, revokedRefresh.Body.String())
	}

	activeForUser := performJSON(t, router, http.MethodGet, "/v1/admin/sessions?user_id="+userIDString(otherUser.ID)+"&status=active", "", adminPair.AccessToken)
	if activeForUser.Code != http.StatusOK {
		t.Fatalf("active user sessions status = %d, want %d body=%s", activeForUser.Code, http.StatusOK, activeForUser.Body.String())
	}
	if total := numberFromAny(decodeData(t, activeForUser)["total"]); total != 0 {
		t.Fatalf("active sessions total = %d, want 0 body=%s", total, activeForUser.Body.String())
	}

	revoked := performJSON(t, router, http.MethodGet, "/v1/admin/sessions?status=revoked&search=other", "", adminPair.AccessToken)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoked sessions status = %d, want %d body=%s", revoked.Code, http.StatusOK, revoked.Body.String())
	}
	revokedItems := asSlice(t, decodeData(t, revoked)["sessions"], "sessions")
	revokedSession := findItemByStringField(t, revokedItems, "id", otherPair.SessionID)
	if got := stringFromAny(revokedSession["status"]); got != "revoked" {
		t.Fatalf("revoked session status = %q, want revoked", got)
	}
}

func TestAccountMeReturnsCurrentUserAndAdminStatus(t *testing.T) {
	router, db, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	regularPair := issueIntegrationTokens(t, sessionService, *regularUser, 0)
	adminPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)
	makeSystemUser(t, db, otherUser.ID)

	regular := performJSON(t, router, http.MethodGet, "/v1/account/me", "", regularPair.AccessToken)
	if regular.Code != http.StatusOK {
		t.Fatalf("regular account status = %d, want %d body=%s", regular.Code, http.StatusOK, regular.Body.String())
	}
	regularData := decodeData(t, regular)
	regularUserData := asMap(t, regularData["user"], "user")
	if got := stringFromAny(regularUserData["email"]); got != regularUser.Email {
		t.Fatalf("regular email = %q, want %q", got, regularUser.Email)
	}
	if got := boolFromAny(regularData["is_admin"]); got {
		t.Fatalf("regular is_admin = true, want false")
	}

	admin := performJSON(t, router, http.MethodGet, "/v1/account/me", "", adminPair.AccessToken)
	if admin.Code != http.StatusOK {
		t.Fatalf("admin account status = %d, want %d body=%s", admin.Code, http.StatusOK, admin.Body.String())
	}
	adminData := decodeData(t, admin)
	if got := boolFromAny(adminData["is_admin"]); !got {
		t.Fatalf("admin is_admin = false, want true")
	}
}

func TestAccountSessionsAreScopedToAuthenticatedUser(t *testing.T) {
	router, _, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	ownPair := issueIntegrationTokens(t, sessionService, *regularUser, 0)
	otherPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)

	list := performJSON(t, router, http.MethodGet, "/v1/account/sessions", "", ownPair.AccessToken)
	if list.Code != http.StatusOK {
		t.Fatalf("account sessions status = %d, want %d body=%s", list.Code, http.StatusOK, list.Body.String())
	}
	sessions := asSlice(t, decodeData(t, list)["sessions"], "sessions")
	ownSession := findItemByStringField(t, sessions, "id", ownPair.SessionID)
	if got := boolFromAny(ownSession["current"]); !got {
		t.Fatalf("own current session current = false, want true")
	}
	if got := stringFromAny(ownSession["status"]); got != "active" {
		t.Fatalf("own current session status = %q, want active", got)
	}
	if itemWithStringField(sessions, "id", otherPair.SessionID) != nil {
		t.Fatalf("account sessions leaked other user's session %s in %#v", otherPair.SessionID, sessions)
	}
}

func TestAccountSessionRevocationStaysScopedToCurrentUser(t *testing.T) {
	router, db, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	ownPair := issueIntegrationTokens(t, sessionService, *regularUser, 0)
	ownSecondPair := issueIntegrationTokens(t, sessionService, *regularUser, 0)
	otherPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)

	revokeOther := performJSON(t, router, http.MethodPost, "/v1/account/sessions/"+otherPair.SessionID+"/revoke", `{}`, ownPair.AccessToken)
	if revokeOther.Code != http.StatusNotFound {
		t.Fatalf("revoke other session status = %d, want %d body=%s", revokeOther.Code, http.StatusNotFound, revokeOther.Body.String())
	}
	assertSessionStillActive(t, db, otherPair.SessionID)

	revokeOwn := performJSON(t, router, http.MethodPost, "/v1/account/sessions/"+ownSecondPair.SessionID+"/revoke", `{}`, ownPair.AccessToken)
	if revokeOwn.Code != http.StatusOK {
		t.Fatalf("revoke own session status = %d, want %d body=%s", revokeOwn.Code, http.StatusOK, revokeOwn.Body.String())
	}
	assertSessionRevoked(t, db, ownSecondPair.SessionID)
	assertSessionStillActive(t, db, ownPair.SessionID)

	logoutAll := performJSON(t, router, http.MethodPost, "/v1/account/logout-all", `{}`, ownPair.AccessToken)
	if logoutAll.Code != http.StatusOK {
		t.Fatalf("account logout-all status = %d, want %d body=%s", logoutAll.Code, http.StatusOK, logoutAll.Body.String())
	}
	assertSessionRevoked(t, db, ownPair.SessionID)
	assertSessionRevoked(t, db, ownSecondPair.SessionID)
	assertSessionStillActive(t, db, otherPair.SessionID)

	revokedAccess := performJSON(t, router, http.MethodGet, "/v1/account/me", "", ownPair.AccessToken)
	if revokedAccess.Code != http.StatusUnauthorized {
		t.Fatalf("revoked access status = %d, want %d body=%s", revokedAccess.Code, http.StatusUnauthorized, revokedAccess.Body.String())
	}
}

func TestAccountProfileCanBeViewedAndUpdated(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	view := performJSON(t, router, http.MethodGet, "/v1/account/profile", "", pair.AccessToken)
	if view.Code != http.StatusOK {
		t.Fatalf("account profile status = %d, want %d body=%s", view.Code, http.StatusOK, view.Body.String())
	}
	viewData := decodeData(t, view)
	profile := asMap(t, viewData["profile"], "profile")
	if got := stringFromAny(profile["email"]); got != regularUser.Email {
		t.Fatalf("profile email = %q, want %q", got, regularUser.Email)
	}
	if got := stringFromAny(profile["username"]); got == "" {
		t.Fatalf("profile username is empty: %#v", profile)
	}

	update := performJSON(t, router, http.MethodPatch, "/v1/account/profile", `{"username":"member-renamed","nickname":"Member Hero","display_name":"Member Hero","locale":"zh-CN","avatar_url":"https://cdn.example.com/avatar.png"}`, pair.AccessToken)
	if update.Code != http.StatusOK {
		t.Fatalf("update profile status = %d, want %d body=%s", update.Code, http.StatusOK, update.Body.String())
	}
	updateData := decodeData(t, update)
	updatedProfile := asMap(t, updateData["profile"], "profile")
	if got := stringFromAny(updatedProfile["username"]); got != "member-renamed" {
		t.Fatalf("updated username = %q, want member-renamed", got)
	}
	if got := stringFromAny(updatedProfile["nickname"]); got != "Member Hero" {
		t.Fatalf("updated nickname = %q, want Member Hero", got)
	}
	if got := stringFromAny(updatedProfile["locale"]); got != "zh-CN" {
		t.Fatalf("updated locale = %q, want zh-CN", got)
	}
	if got := stringFromAny(updatedProfile["avatar_url"]); got != "https://cdn.example.com/avatar.png" {
		t.Fatalf("updated avatar_url = %q, want https://cdn.example.com/avatar.png", got)
	}

	var stored store.User
	if err := db.First(&stored, regularUser.ID).Error; err != nil {
		t.Fatalf("db.First(user) error = %v", err)
	}
	if stored.Username != "member-renamed" {
		t.Fatalf("stored username = %q, want member-renamed", stored.Username)
	}
	if stored.Nickname != "Member Hero" {
		t.Fatalf("stored nickname = %q, want Member Hero", stored.Nickname)
	}
	if stored.DisplayName != "Member Hero" {
		t.Fatalf("stored display_name = %q, want Member Hero", stored.DisplayName)
	}
	if stored.Locale != "zh-CN" {
		t.Fatalf("stored locale = %q, want zh-CN", stored.Locale)
	}
	if stored.AvatarURL != "https://cdn.example.com/avatar.png" {
		t.Fatalf("stored avatar_url = %q, want https://cdn.example.com/avatar.png", stored.AvatarURL)
	}
}

func TestAccountAvatarUploadStoresImageAndUpdatesProfile(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	file, err := writer.CreateFormFile("avatar", "avatar.png")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := file.Write(tinyPNG()); err != nil {
		t.Fatalf("write avatar: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart writer close: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/account/avatar", body)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("avatar upload status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	data := decodeData(t, recorder)
	avatarURL := stringFromAny(data["avatar_url"])
	if !strings.HasPrefix(avatarURL, "/uploads/avatars/") {
		t.Fatalf("avatar_url = %q, want /uploads/avatars/ prefix", avatarURL)
	}

	var stored store.User
	if err := db.First(&stored, regularUser.ID).Error; err != nil {
		t.Fatalf("db.First(user) error = %v", err)
	}
	if stored.AvatarURL != avatarURL {
		t.Fatalf("stored avatar_url = %q, want %q", stored.AvatarURL, avatarURL)
	}

	static := httptest.NewRequest(http.MethodGet, avatarURL, nil)
	staticRecorder := httptest.NewRecorder()
	router.ServeHTTP(staticRecorder, static)
	if staticRecorder.Code != http.StatusOK {
		t.Fatalf("static avatar status = %d, want %d body=%s", staticRecorder.Code, http.StatusOK, staticRecorder.Body.String())
	}
}

func TestAccountPasswordChangeRequiresCurrentPasswordAndInvalidatesToken(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	oldHash, err := auth.HashPassword("old-password-123")
	if err != nil {
		t.Fatalf("HashPassword(old) error = %v", err)
	}
	if err := db.Model(&store.User{}).Where("id = ?", regularUser.ID).Updates(map[string]any{
		"password_hash": oldHash,
	}).Error; err != nil {
		t.Fatalf("set old password hash: %v", err)
	}
	regularUser.PasswordHash = oldHash
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	wrongCurrent := performJSON(t, router, http.MethodPost, "/v1/account/password/change", `{"current_password":"wrong-password","new_password":"new-password-456"}`, pair.AccessToken)
	if wrongCurrent.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password status = %d, want %d body=%s", wrongCurrent.Code, http.StatusUnauthorized, wrongCurrent.Body.String())
	}
	assertSessionStillActive(t, db, pair.SessionID)

	change := performJSON(t, router, http.MethodPost, "/v1/account/password/change", `{"current_password":"old-password-123","new_password":"new-password-456"}`, pair.AccessToken)
	if change.Code != http.StatusOK {
		t.Fatalf("password change status = %d, want %d body=%s", change.Code, http.StatusOK, change.Body.String())
	}
	data := decodeData(t, change)
	if got := boolFromAny(data["changed"]); !got {
		t.Fatalf("changed = false, want true")
	}

	var updated store.User
	if err := db.First(&updated, regularUser.ID).Error; err != nil {
		t.Fatalf("db.First(updated user) error = %v", err)
	}
	if updated.TokenVersion != regularUser.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d", updated.TokenVersion, regularUser.TokenVersion+1)
	}
	if err := auth.CheckPassword(updated.PasswordHash, "new-password-456"); err != nil {
		t.Fatalf("new password hash check error = %v", err)
	}
	if err := auth.CheckPassword(updated.PasswordHash, "old-password-123"); err == nil {
		t.Fatalf("old password still matches updated hash")
	}

	staleAccess := performJSON(t, router, http.MethodGet, "/v1/account/me", "", pair.AccessToken)
	if staleAccess.Code != http.StatusUnauthorized {
		t.Fatalf("stale access status = %d, want %d body=%s", staleAccess.Code, http.StatusUnauthorized, staleAccess.Body.String())
	}

	var logEntry store.AuditLog
	if err := db.Where("actor_user_id = ? AND action = ?", regularUser.ID, audit.ActionPasswordChanged).First(&logEntry).Error; err != nil {
		t.Fatalf("password change audit log missing: %v", err)
	}
}

func TestAccountPasswordChangeRollsBackWhenAuditCannotBeRecorded(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	oldHash, err := auth.HashPassword("old-password-123")
	if err != nil {
		t.Fatalf("HashPassword(old) error = %v", err)
	}
	if err := db.Model(&store.User{}).Where("id = ?", regularUser.ID).Updates(map[string]any{
		"password_hash": oldHash,
	}).Error; err != nil {
		t.Fatalf("set old password hash: %v", err)
	}
	regularUser.PasswordHash = oldHash
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)
	if err := db.Migrator().DropTable(&store.AuditLog{}); err != nil {
		t.Fatalf("drop audit_logs: %v", err)
	}

	change := performJSON(t, router, http.MethodPost, "/v1/account/password/change", `{"current_password":"old-password-123","new_password":"new-password-456"}`, pair.AccessToken)
	if change.Code != http.StatusInternalServerError {
		t.Fatalf("password change status = %d, want %d body=%s", change.Code, http.StatusInternalServerError, change.Body.String())
	}

	var updated store.User
	if err := db.First(&updated, regularUser.ID).Error; err != nil {
		t.Fatalf("db.First(updated user) error = %v", err)
	}
	if updated.TokenVersion != regularUser.TokenVersion {
		t.Fatalf("token_version = %d, want unchanged %d", updated.TokenVersion, regularUser.TokenVersion)
	}
	if err := auth.CheckPassword(updated.PasswordHash, "old-password-123"); err != nil {
		t.Fatalf("old password hash check error = %v", err)
	}
}

func TestAccountTwoFactorLifecyclePersistsStateAndWritesAuditLogs(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	initialStatus := performJSON(t, router, http.MethodGet, "/v1/account/2fa/status", "", pair.AccessToken)
	if initialStatus.Code != http.StatusOK {
		t.Fatalf("initial 2fa status = %d, want %d body=%s", initialStatus.Code, http.StatusOK, initialStatus.Body.String())
	}
	initialData := decodeData(t, initialStatus)
	if got := boolFromAny(initialData["enabled"]); got {
		t.Fatalf("initial enabled = true, want false")
	}
	if got := boolFromAny(initialData["recovery_codes_available"]); got {
		t.Fatalf("initial recovery_codes_available = true, want false")
	}

	setup := performJSON(t, router, http.MethodPost, "/v1/account/2fa/setup/start", `{}`, pair.AccessToken)
	if setup.Code != http.StatusOK {
		t.Fatalf("2fa setup status = %d, want %d body=%s", setup.Code, http.StatusOK, setup.Body.String())
	}
	setupData := decodeData(t, setup)
	secret := stringFromAny(setupData["secret"])
	if secret == "" {
		t.Fatalf("setup secret is empty: %#v", setupData)
	}
	if got := stringFromAny(setupData["otpauth_url"]); !strings.HasPrefix(got, "otpauth://totp/") {
		t.Fatalf("otpauth_url = %q, want otpauth totp URL", got)
	}

	code := totpCodeForTest(t, secret, time.Now().UTC())
	verify := performJSON(t, router, http.MethodPost, "/v1/account/2fa/verify", `{"code":"`+code+`"}`, pair.AccessToken)
	if verify.Code != http.StatusOK {
		t.Fatalf("2fa verify status = %d, want %d body=%s", verify.Code, http.StatusOK, verify.Body.String())
	}
	verifyData := decodeData(t, verify)
	if got := boolFromAny(verifyData["verified"]); !got {
		t.Fatalf("verified = false, want true")
	}
	recoveryCodes := asSlice(t, verifyData["recovery_codes"], "recovery_codes")
	if len(recoveryCodes) != 10 {
		t.Fatalf("recovery code count = %d, want 10 body=%s", len(recoveryCodes), verify.Body.String())
	}

	var persisted struct {
		Enabled            bool
		RecoveryCodeHashes string
	}
	if err := db.Raw("SELECT enabled, recovery_code_hashes FROM user_two_factors WHERE user_id = ?", regularUser.ID).Scan(&persisted).Error; err != nil {
		t.Fatalf("load persisted 2fa state: %v", err)
	}
	if !persisted.Enabled {
		t.Fatalf("persisted enabled = false, want true")
	}
	firstRecoveryCode := stringFromAny(recoveryCodes[0])
	if firstRecoveryCode == "" {
		t.Fatalf("first recovery code is empty: %#v", recoveryCodes)
	}
	if strings.Contains(persisted.RecoveryCodeHashes, firstRecoveryCode) {
		t.Fatalf("persisted recovery code hashes leaked raw code %q", firstRecoveryCode)
	}

	enabledStatus := performJSON(t, router, http.MethodGet, "/v1/account/2fa/status", "", pair.AccessToken)
	if enabledStatus.Code != http.StatusOK {
		t.Fatalf("enabled 2fa status = %d, want %d body=%s", enabledStatus.Code, http.StatusOK, enabledStatus.Body.String())
	}
	enabledData := decodeData(t, enabledStatus)
	if got := boolFromAny(enabledData["enabled"]); !got {
		t.Fatalf("enabled status = false, want true")
	}
	if got := boolFromAny(enabledData["recovery_codes_available"]); !got {
		t.Fatalf("enabled recovery_codes_available = false, want true")
	}
	if got := stringFromAny(enabledData["method"]); got != "totp" {
		t.Fatalf("enabled method = %q, want totp", got)
	}

	badRegenerate := performJSON(t, router, http.MethodPost, "/v1/account/2fa/recovery-codes/regenerate", `{"code":"000000"}`, pair.AccessToken)
	if badRegenerate.Code != http.StatusUnauthorized {
		t.Fatalf("bad recovery regeneration status = %d, want %d body=%s", badRegenerate.Code, http.StatusUnauthorized, badRegenerate.Body.String())
	}

	regenerateCode := totpCodeForTest(t, secret, time.Now().UTC())
	regenerate := performJSON(t, router, http.MethodPost, "/v1/account/2fa/recovery-codes/regenerate", `{"code":"`+regenerateCode+`"}`, pair.AccessToken)
	if regenerate.Code != http.StatusOK {
		t.Fatalf("recovery regeneration status = %d, want %d body=%s", regenerate.Code, http.StatusOK, regenerate.Body.String())
	}
	regenerateData := decodeData(t, regenerate)
	regeneratedCodes := asSlice(t, regenerateData["recovery_codes"], "recovery_codes")
	if len(regeneratedCodes) != 10 {
		t.Fatalf("regenerated recovery code count = %d, want 10 body=%s", len(regeneratedCodes), regenerate.Body.String())
	}

	badDisable := performJSON(t, router, http.MethodPost, "/v1/account/2fa/disable", `{"code":"000000"}`, pair.AccessToken)
	if badDisable.Code != http.StatusUnauthorized {
		t.Fatalf("bad 2fa disable status = %d, want %d body=%s", badDisable.Code, http.StatusUnauthorized, badDisable.Body.String())
	}

	disableCode := totpCodeForTest(t, secret, time.Now().UTC())
	disable := performJSON(t, router, http.MethodPost, "/v1/account/2fa/disable", `{"code":"`+disableCode+`"}`, pair.AccessToken)
	if disable.Code != http.StatusOK {
		t.Fatalf("2fa disable status = %d, want %d body=%s", disable.Code, http.StatusOK, disable.Body.String())
	}
	disableData := decodeData(t, disable)
	if got := boolFromAny(disableData["disabled"]); !got {
		t.Fatalf("disabled = false, want true")
	}

	finalStatus := performJSON(t, router, http.MethodGet, "/v1/account/2fa/status", "", pair.AccessToken)
	if finalStatus.Code != http.StatusOK {
		t.Fatalf("final 2fa status = %d, want %d body=%s", finalStatus.Code, http.StatusOK, finalStatus.Body.String())
	}
	finalData := decodeData(t, finalStatus)
	if got := boolFromAny(finalData["enabled"]); got {
		t.Fatalf("final enabled = true, want false")
	}
	if got := boolFromAny(finalData["recovery_codes_available"]); got {
		t.Fatalf("final recovery_codes_available = true, want false")
	}

	var auditCount int64
	if err := db.Model(&store.AuditLog{}).
		Where("actor_user_id = ? AND action IN ?", regularUser.ID, []string{
			"two_factor_enabled",
			"two_factor_recovery_codes_regenerated",
			"two_factor_disabled",
		}).
		Count(&auditCount).Error; err != nil {
		t.Fatalf("count 2fa audit logs: %v", err)
	}
	if auditCount != 3 {
		t.Fatalf("2fa audit log count = %d, want 3", auditCount)
	}
}

func TestAccountLoginMethodsExposeLocalAndGitHubBindings(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	now := time.Now().UTC()
	if err := db.Model(&store.User{}).Where("id = ?", regularUser.ID).Update("email_verified_at", now).Error; err != nil {
		t.Fatalf("verify email: %v", err)
	}
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	identity := store.UserIdentity{
		UserID:         regularUser.ID,
		Provider:       "github",
		ProviderUserID: "github-42",
		Email:          regularUser.Email,
		EmailVerified:  true,
		Username:       "octocat",
		DisplayName:    "The Octocat",
		AvatarURL:      "https://avatars.example.com/octocat.png",
	}
	if err := db.Create(&identity).Error; err != nil {
		t.Fatalf("db.Create(identity) error = %v", err)
	}

	list := performJSON(t, router, http.MethodGet, "/v1/account/login-methods", "", pair.AccessToken)
	if list.Code != http.StatusOK {
		t.Fatalf("login methods status = %d, want %d body=%s", list.Code, http.StatusOK, list.Body.String())
	}
	data := decodeData(t, list)
	methods := asSlice(t, data["methods"], "methods")

	passwordMethod := findItemByStringField(t, methods, "key", "password")
	if got := boolFromAny(passwordMethod["bound"]); !got {
		t.Fatalf("password bound = false, want true")
	}
	if got := stringFromAny(passwordMethod["status"]); got != "enabled" {
		t.Fatalf("password status = %q, want enabled", got)
	}

	emailMethod := findItemByStringField(t, methods, "key", "email")
	if got := stringFromAny(emailMethod["status"]); got != "verified" {
		t.Fatalf("email status = %q, want verified", got)
	}
	if got := stringFromAny(emailMethod["identifier"]); got != regularUser.Email {
		t.Fatalf("email identifier = %q, want %q", got, regularUser.Email)
	}

	githubMethod := findItemByStringField(t, methods, "key", "github")
	if got := boolFromAny(githubMethod["bound"]); !got {
		t.Fatalf("github bound = false, want true")
	}
	if got := stringFromAny(githubMethod["status"]); got != "bound" {
		t.Fatalf("github status = %q, want bound", got)
	}
	if got := stringFromAny(githubMethod["identifier"]); got != "octocat" {
		t.Fatalf("github identifier = %q, want octocat", got)
	}
}

func TestAccountLoginMethodBindStartStoresUserScopedOAuthState(t *testing.T) {
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
	mini := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() {
		_ = redisClient.Close()
	})

	cfg := config.Config{
		JWTKeyID:            "test-key",
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		GitHubOAuthEnabled:  true,
		GitHubClientID:      "client-id",
		GitHubClientSecret:  "client-secret",
		GitHubRedirectURI:   "https://auth.example.com/v1/external/github/callback",
		BrowserLoginURL:     "https://auth.example.com/login",
		PublicIssuerURL:     "https://auth.example.com",
		BrowserCookieSecure: true,
	}
	router := buildRouter(cfg, db, redisClient, privateKey)
	sessionService := session.NewService(db, cfg, privateKey)
	user := &store.User{
		Email:        "member@example.com",
		DisplayName:  "member",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("db.Create(user) error = %v", err)
	}
	pair := issueIntegrationTokens(t, sessionService, *user, 0)

	start := performJSON(t, router, http.MethodPost, "/v1/account/login-methods/github/bind/start", `{"return_to":"/account?tab=login"}`, pair.AccessToken)
	if start.Code != http.StatusOK {
		t.Fatalf("bind start status = %d, want %d body=%s", start.Code, http.StatusOK, start.Body.String())
	}
	data := decodeData(t, start)
	startURL := stringFromAny(data["start_url"])
	parsed, err := url.Parse(startURL)
	if err != nil {
		t.Fatalf("parse start_url %q: %v", startURL, err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("start_url = %q, missing state", startURL)
	}
	if got := parsed.Query().Get("client_id"); got != "client-id" {
		t.Fatalf("client_id = %q, want client-id", got)
	}
	if got := parsed.Query().Get("redirect_uri"); got != cfg.GitHubRedirectURI {
		t.Fatalf("redirect_uri = %q, want %q", got, cfg.GitHubRedirectURI)
	}

	foundCookie := false
	for _, cookie := range start.Result().Cookies() {
		if cookie.Name != "goauth_github_oauth_state" {
			continue
		}
		foundCookie = true
		if cookie.Value != state {
			t.Fatalf("state cookie = %q, want %q", cookie.Value, state)
		}
		if !cookie.HttpOnly || !cookie.Secure {
			t.Fatalf("state cookie flags = httpOnly:%v secure:%v, want true/true", cookie.HttpOnly, cookie.Secure)
		}
	}
	if !foundCookie {
		t.Fatal("missing github oauth state cookie")
	}

	payload, err := idp.NewExchangeStore(redisClient).ConsumeOAuthState(context.Background(), state)
	if err != nil {
		t.Fatalf("consume oauth state: %v", err)
	}
	if payload.Flow != "bind" {
		t.Fatalf("flow = %q, want bind", payload.Flow)
	}
	if payload.UserID != user.ID {
		t.Fatalf("user_id = %d, want %d", payload.UserID, user.ID)
	}
	if payload.ReturnTo != "/account?tab=login" {
		t.Fatalf("return_to = %q, want account login tab", payload.ReturnTo)
	}
}

func TestAccountAuthorizedAppsListAndRevokeStayScopedToCurrentUser(t *testing.T) {
	router, db, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	client := store.OAuthClient{
		TenantID:                1,
		ClientID:                "notes-client",
		ClientSecretHash:        "hash",
		Name:                    "Notes",
		RedirectURIs:            datatypes.JSON([]byte(`["https://notes.example.com/callback"]`)),
		AllowedScopes:           datatypes.JSON([]byte(`["openid","profile"]`)),
		GrantTypes:              datatypes.JSON([]byte(`["authorization_code","refresh_token"]`)),
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("db.Create(client) error = %v", err)
	}
	otherClient := store.OAuthClient{
		TenantID:                1,
		ClientID:                "tasks-client",
		ClientSecretHash:        "hash",
		Name:                    "Tasks",
		RedirectURIs:            datatypes.JSON([]byte(`["https://tasks.example.com/callback"]`)),
		AllowedScopes:           datatypes.JSON([]byte(`["openid"]`)),
		GrantTypes:              datatypes.JSON([]byte(`["authorization_code","refresh_token"]`)),
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}
	if err := db.Create(&otherClient).Error; err != nil {
		t.Fatalf("db.Create(otherClient) error = %v", err)
	}

	notesPair := issueIntegrationTokensForClient(t, sessionService, *regularUser, 0, "notes-client")
	otherNotesPair := issueIntegrationTokensForClient(t, sessionService, *otherUser, 0, "tasks-client")

	list := performJSON(t, router, http.MethodGet, "/v1/account/authorized-apps", "", pair.AccessToken)
	if list.Code != http.StatusOK {
		t.Fatalf("authorized apps status = %d, want %d body=%s", list.Code, http.StatusOK, list.Body.String())
	}
	data := decodeData(t, list)
	apps := asSlice(t, data["apps"], "apps")
	app := findItemByStringField(t, apps, "client_id", "notes-client")
	if got := stringFromAny(app["name"]); got != "Notes" {
		t.Fatalf("authorized app name = %q, want Notes", got)
	}
	if got := boolFromAny(app["active"]); !got {
		t.Fatalf("authorized app active = false, want true")
	}
	if itemWithStringField(apps, "client_id", "tasks-client") != nil {
		t.Fatalf("authorized apps leaked other user's client: %#v", apps)
	}

	revoke := performJSON(t, router, http.MethodDelete, "/v1/account/authorized-apps/notes-client", "", pair.AccessToken)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke app status = %d, want %d body=%s", revoke.Code, http.StatusOK, revoke.Body.String())
	}

	assertSessionRevoked(t, db, notesPair.SessionID)
	assertSessionStillActive(t, db, pair.SessionID)
	assertSessionStillActive(t, db, otherNotesPair.SessionID)
}

func TestAccountActivityReturnsRecentUserScopedTimeline(t *testing.T) {
	router, db, sessionService, regularUser, otherUser := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	now := time.Now().UTC()
	entries := []store.AuditLog{
		{
			ActorUserID: regularUser.ID,
			Action:      audit.ActionUserUpdated,
			TargetType:  audit.TargetTypeUser,
			TargetID:    userIDString(regularUser.ID),
			Metadata:    datatypes.JSON([]byte(`{"fields":["nickname","locale"],"source":"account_profile"}`)),
			CreatedAt:   now.Add(-time.Minute),
		},
		{
			ActorUserID: regularUser.ID,
			Action:      audit.ActionExternalIdentityChanged,
			TargetType:  audit.TargetTypeIdentity,
			TargetID:    "1",
			Metadata:    datatypes.JSON([]byte(`{"change":"bound","provider":"github","identity_username":"octocat"}`)),
			CreatedAt:   now,
		},
		{
			ActorUserID: otherUser.ID,
			Action:      audit.ActionPasswordReset,
			TargetType:  audit.TargetTypeUser,
			TargetID:    userIDString(otherUser.ID),
			Metadata:    datatypes.JSON([]byte(`{"source":"self_service"}`)),
			CreatedAt:   now.Add(time.Minute),
		},
	}
	if err := db.Create(&entries).Error; err != nil {
		t.Fatalf("db.Create(audit logs) error = %v", err)
	}

	list := performJSON(t, router, http.MethodGet, "/v1/account/activity?limit=2", "", pair.AccessToken)
	if list.Code != http.StatusOK {
		t.Fatalf("account activity status = %d, want %d body=%s", list.Code, http.StatusOK, list.Body.String())
	}
	data := decodeData(t, list)
	items := asSlice(t, data["items"], "items")
	if len(items) != 2 {
		t.Fatalf("activity items length = %d, want 2 body=%s", len(items), list.Body.String())
	}

	first := asMap(t, items[0], "items[0]")
	if got := stringFromAny(first["action"]); got != audit.ActionExternalIdentityChanged {
		t.Fatalf("first action = %q, want %q", got, audit.ActionExternalIdentityChanged)
	}
	if got := stringFromAny(first["category"]); got != "login_method" {
		t.Fatalf("first category = %q, want login_method", got)
	}
	if got := stringFromAny(first["title"]); !strings.Contains(got, "GitHub") {
		t.Fatalf("first title = %q, want GitHub", got)
	}

	second := asMap(t, items[1], "items[1]")
	if got := stringFromAny(second["action"]); got != audit.ActionUserUpdated {
		t.Fatalf("second action = %q, want %q", got, audit.ActionUserUpdated)
	}
	if got := stringFromAny(second["category"]); got != "profile" {
		t.Fatalf("second category = %q, want profile", got)
	}
}

func TestAccountOverviewAggregatesStatsAlertsAndRecentActivity(t *testing.T) {
	router, db, sessionService, regularUser, _ := newIntegrationRouter(t)
	pair := issueIntegrationTokens(t, sessionService, *regularUser, 0)

	identity := store.UserIdentity{
		UserID:         regularUser.ID,
		Provider:       "github",
		ProviderUserID: "github-42",
		Email:          regularUser.Email,
		EmailVerified:  true,
		Username:       "octocat",
		DisplayName:    "The Octocat",
	}
	if err := db.Create(&identity).Error; err != nil {
		t.Fatalf("db.Create(identity) error = %v", err)
	}

	client := store.OAuthClient{
		TenantID:                1,
		ClientID:                "notes-client",
		ClientSecretHash:        "hash",
		Name:                    "Notes",
		RedirectURIs:            datatypes.JSON([]byte(`["https://notes.example.com/callback"]`)),
		AllowedScopes:           datatypes.JSON([]byte(`["openid","profile"]`)),
		GrantTypes:              datatypes.JSON([]byte(`["authorization_code","refresh_token"]`)),
		TokenEndpointAuthMethod: "client_secret_post",
		Status:                  "active",
	}
	if err := db.Create(&client).Error; err != nil {
		t.Fatalf("db.Create(client) error = %v", err)
	}
	_ = issueIntegrationTokensForClient(t, sessionService, *regularUser, 0, "notes-client")

	logEntry := store.AuditLog{
		ActorUserID: regularUser.ID,
		Action:      audit.ActionExternalIdentityChanged,
		TargetType:  audit.TargetTypeIdentity,
		TargetID:    "1",
		Metadata:    datatypes.JSON([]byte(`{"change":"bound","provider":"github","identity_username":"octocat"}`)),
		CreatedAt:   time.Now().UTC(),
	}
	if err := db.Create(&logEntry).Error; err != nil {
		t.Fatalf("db.Create(logEntry) error = %v", err)
	}

	overview := performJSON(t, router, http.MethodGet, "/v1/account/overview", "", pair.AccessToken)
	if overview.Code != http.StatusOK {
		t.Fatalf("account overview status = %d, want %d body=%s", overview.Code, http.StatusOK, overview.Body.String())
	}
	data := decodeData(t, overview)
	stats := asMap(t, data["stats"], "stats")
	if got := numberFromAny(stats["active_sessions"]); got != 2 {
		t.Fatalf("active_sessions = %d, want 2", got)
	}
	if got := numberFromAny(stats["login_methods"]); got != 3 {
		t.Fatalf("login_methods = %d, want 3", got)
	}
	if got := numberFromAny(stats["authorized_apps"]); got != 1 {
		t.Fatalf("authorized_apps = %d, want 1", got)
	}

	alerts := asSlice(t, data["alerts"], "alerts")
	emailAlert := findItemByStringField(t, alerts, "key", "email_unverified")
	if got := stringFromAny(emailAlert["severity"]); got != "warning" {
		t.Fatalf("email alert severity = %q, want warning", got)
	}

	recentActivity := asSlice(t, data["recent_activity"], "recent_activity")
	if len(recentActivity) != 1 {
		t.Fatalf("recent activity length = %d, want 1 body=%s", len(recentActivity), overview.Body.String())
	}
}

func TestAdminOAuthClientSecretRotation(t *testing.T) {
	router, db, sessionService, adminUser, _ := newIntegrationRouter(t)
	makeSystemUser(t, db, adminUser.ID)
	pair := issueIntegrationTokens(t, sessionService, *adminUser, 0)

	tenantRecord := store.Tenant{Name: "App Tenant", Slug: "app-tenant", Status: store.TenantStatusActive}
	if err := db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("db.Create(tenant) error = %v", err)
	}
	oidcService := oidc.NewService(db, config.Config{RefreshTokenTTL: 30 * 24 * time.Hour}, mustRSAKey(t))
	client, err := oidcService.CreateClient(t.Context(), oidc.CreateClientInput{
		TenantID:                tenantRecord.ID,
		ClientID:                "admin-rotate-client",
		ClientSecret:            "old-secret",
		Name:                    "Admin Rotate Client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		AllowedScopes:           []string{"openid"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}

	recorder := performJSON(t, router, http.MethodPost, "/v1/admin/oauth-clients/"+client.ClientID+"/rotate-secret", `{}`, pair.AccessToken)
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "client_secret") {
		t.Fatalf("body = %s, want client_secret", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "client_secret_hash") {
		t.Fatalf("body leaked client_secret_hash: %s", recorder.Body.String())
	}
}

func TestAdminManagementListsReturnUsablePayloads(t *testing.T) {
	router, db, sessionService, adminUser, otherUser := newIntegrationRouter(t)
	makeSystemUser(t, db, adminUser.ID)
	pair := issueIntegrationTokens(t, sessionService, *adminUser, 0)

	tenantRecord := store.Tenant{Name: "Community Forum", Slug: "community-forum", Status: store.TenantStatusActive}
	if err := db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("db.Create(tenant) error = %v", err)
	}
	member := store.TenantMember{TenantID: tenantRecord.ID, UserID: otherUser.ID, Status: store.MemberStatusActive}
	if err := db.Create(&member).Error; err != nil {
		t.Fatalf("db.Create(member) error = %v", err)
	}
	role := store.Role{TenantID: tenantRecord.ID, Name: "Moderator", Code: "moderator", Description: "Moderates forum content"}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("db.Create(role) error = %v", err)
	}
	permission := store.Permission{Resource: "post", Action: "moderate", Code: "post:moderate", Description: "Moderate posts"}
	if err := db.Create(&permission).Error; err != nil {
		t.Fatalf("db.Create(permission) error = %v", err)
	}
	if err := db.Create(&store.RolePermission{RoleID: role.ID, PermissionID: permission.ID}).Error; err != nil {
		t.Fatalf("db.Create(role permission) error = %v", err)
	}
	if err := db.Create(&store.MemberRole{MemberID: member.ID, RoleID: role.ID}).Error; err != nil {
		t.Fatalf("db.Create(member role) error = %v", err)
	}
	_ = issueIntegrationTokens(t, sessionService, *otherUser, tenantRecord.ID)

	users := performJSON(t, router, http.MethodGet, "/v1/admin/users?search=other&page=1&page_size=1&sort=email_desc", "", pair.AccessToken)
	if users.Code != http.StatusOK {
		t.Fatalf("users status = %d, want %d body=%s", users.Code, http.StatusOK, users.Body.String())
	}
	userData := decodeData(t, users)
	userItems := asSlice(t, userData["users"], "users")
	if len(userItems) != 1 {
		t.Fatalf("users length = %d, want 1 body=%s", len(userItems), users.Body.String())
	}
	if total := numberFromAny(userData["total"]); total != 1 {
		t.Fatalf("users total = %d, want 1 body=%s", total, users.Body.String())
	}
	userItem := asMap(t, userItems[0], "users[0]")
	if got := stringFromAny(userItem["email"]); got != "other@example.com" {
		t.Fatalf("user email = %q, want other@example.com", got)
	}
	if got := stringFromAny(userItem["tenant"]); !strings.Contains(got, "Community Forum") {
		t.Fatalf("user tenant = %q, want Community Forum", got)
	}
	if got := stringFromAny(userItem["role"]); !strings.Contains(got, "Moderator") {
		t.Fatalf("user role = %q, want Moderator", got)
	}
	if _, ok := userItem["email_verified"]; !ok {
		t.Fatalf("user payload missing email_verified: %#v", userItem)
	}
	if got := stringFromAny(userItem["last_login"]); got == "" {
		t.Fatalf("user last_login is empty: %#v", userItem)
	}

	tenants := performJSON(t, router, http.MethodGet, "/v1/admin/tenants?search=community&page=1&page_size=10", "", pair.AccessToken)
	if tenants.Code != http.StatusOK {
		t.Fatalf("tenants status = %d, want %d body=%s", tenants.Code, http.StatusOK, tenants.Body.String())
	}
	tenantData := decodeData(t, tenants)
	tenantItems := asSlice(t, tenantData["tenants"], "tenants")
	if len(tenantItems) != 1 {
		t.Fatalf("tenants length = %d, want 1 body=%s", len(tenantItems), tenants.Body.String())
	}
	tenantItem := asMap(t, tenantItems[0], "tenants[0]")
	if got := stringFromAny(tenantItem["name"]); got != "Community Forum" {
		t.Fatalf("tenant name = %q, want Community Forum", got)
	}
	if got := numberFromAny(tenantItem["members_count"]); got != 1 {
		t.Fatalf("tenant members_count = %d, want 1", got)
	}
	if got := numberFromAny(tenantItem["roles_count"]); got != 1 {
		t.Fatalf("tenant roles_count = %d, want 1", got)
	}

	roles := performJSON(t, router, http.MethodGet, "/v1/admin/roles?tenant_id="+tenantIDString(tenantRecord.ID), "", pair.AccessToken)
	if roles.Code != http.StatusOK {
		t.Fatalf("roles status = %d, want %d body=%s", roles.Code, http.StatusOK, roles.Body.String())
	}
	roleData := decodeData(t, roles)
	roleItems := asSlice(t, roleData["roles"], "roles")
	if len(roleItems) != 1 {
		t.Fatalf("roles length = %d, want 1 body=%s", len(roleItems), roles.Body.String())
	}
	roleItem := asMap(t, roleItems[0], "roles[0]")
	if got := stringFromAny(roleItem["name"]); got != "Moderator" {
		t.Fatalf("role name = %q, want Moderator", got)
	}
	if got := numberFromAny(roleItem["permissions_count"]); got != 1 {
		t.Fatalf("role permissions_count = %d, want 1", got)
	}
	if got := numberFromAny(roleItem["users_count"]); got != 1 {
		t.Fatalf("role users_count = %d, want 1", got)
	}
	permissionIDs := asSlice(t, roleItem["permission_ids"], "permission_ids")
	if len(permissionIDs) != 1 || numberFromAny(permissionIDs[0]) != int(permission.ID) {
		t.Fatalf("permission_ids = %#v, want [%d]", permissionIDs, permission.ID)
	}
}

func TestAdminBulkUserOperations(t *testing.T) {
	router, db, sessionService, adminUser, otherUser := newIntegrationRouter(t)
	makeSystemUser(t, db, adminUser.ID)
	pair := issueIntegrationTokens(t, sessionService, *adminUser, 0)
	otherPair := issueIntegrationTokens(t, sessionService, *otherUser, 0)
	thirdUser := store.User{
		Email:        "bulk-third@example.com",
		DisplayName:  "Bulk Third",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(&thirdUser).Error; err != nil {
		t.Fatalf("db.Create(thirdUser) error = %v", err)
	}
	thirdPair := issueIntegrationTokens(t, sessionService, thirdUser, 0)
	userIDs := "[" + userIDString(otherUser.ID) + "," + userIDString(thirdUser.ID) + "]"

	disable := performJSON(t, router, http.MethodPost, "/v1/admin/users/bulk-disable", `{"user_ids":`+userIDs+`}`, pair.AccessToken)
	if disable.Code != http.StatusOK {
		t.Fatalf("bulk disable status = %d, want %d body=%s", disable.Code, http.StatusOK, disable.Body.String())
	}
	assertUserStatus(t, db, otherUser.ID, store.UserStatusDisabled)
	assertUserStatus(t, db, thirdUser.ID, store.UserStatusDisabled)

	enable := performJSON(t, router, http.MethodPost, "/v1/admin/users/bulk-enable", `{"user_ids":`+userIDs+`}`, pair.AccessToken)
	if enable.Code != http.StatusOK {
		t.Fatalf("bulk enable status = %d, want %d body=%s", enable.Code, http.StatusOK, enable.Body.String())
	}
	assertUserStatus(t, db, otherUser.ID, store.UserStatusActive)
	assertUserStatus(t, db, thirdUser.ID, store.UserStatusActive)

	tenantRecord := store.Tenant{Name: "Bulk Tenant", Slug: "bulk-tenant", Status: store.TenantStatusActive}
	if err := db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("db.Create(tenant) error = %v", err)
	}
	addMember := performJSON(t, router, http.MethodPost, "/v1/admin/users/bulk-add-to-tenant", `{"tenant_id":`+tenantIDString(tenantRecord.ID)+`,"user_ids":`+userIDs+`}`, pair.AccessToken)
	if addMember.Code != http.StatusOK {
		t.Fatalf("bulk add tenant status = %d, want %d body=%s", addMember.Code, http.StatusOK, addMember.Body.String())
	}
	assertTenantMembershipCount(t, db, tenantRecord.ID, []int64{otherUser.ID, thirdUser.ID}, 2)

	removeMember := performJSON(t, router, http.MethodPost, "/v1/admin/users/bulk-remove-from-tenant", `{"tenant_id":`+tenantIDString(tenantRecord.ID)+`,"user_ids":`+userIDs+`}`, pair.AccessToken)
	if removeMember.Code != http.StatusOK {
		t.Fatalf("bulk remove tenant status = %d, want %d body=%s", removeMember.Code, http.StatusOK, removeMember.Body.String())
	}
	assertTenantMembershipCount(t, db, tenantRecord.ID, []int64{otherUser.ID, thirdUser.ID}, 0)

	logout := performJSON(t, router, http.MethodPost, "/v1/admin/users/bulk-logout", `{"user_ids":`+userIDs+`}`, pair.AccessToken)
	if logout.Code != http.StatusOK {
		t.Fatalf("bulk logout status = %d, want %d body=%s", logout.Code, http.StatusOK, logout.Body.String())
	}
	assertSessionRevoked(t, db, otherPair.SessionID)
	assertSessionRevoked(t, db, thirdPair.SessionID)
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
		JWTKeyID:         "test-key",
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  30 * 24 * time.Hour,
		AvatarStorageDir: t.TempDir(),
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

func issueIntegrationTokensForClient(t *testing.T, service *session.Service, user store.User, tenantID int64, clientID string) *session.TokenPair {
	t.Helper()

	pair, err := service.IssueTokens(t.Context(), session.IssueTokensInput{
		User:     user,
		TenantID: tenantID,
		ClientID: clientID,
	})
	if err != nil {
		t.Fatalf("IssueTokens(%s) error = %v", clientID, err)
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

func assertSessionRevoked(t *testing.T, db *gorm.DB, sessionID string) {
	t.Helper()

	var count int64
	if err := db.Model(&store.RefreshToken{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Count(&count).Error; err != nil {
		t.Fatalf("count active session tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("session %s still has %d active tokens", sessionID, count)
	}
}

func assertUserStatus(t *testing.T, db *gorm.DB, userID int64, status string) {
	t.Helper()

	var userRecord store.User
	if err := db.First(&userRecord, userID).Error; err != nil {
		t.Fatalf("load user %d: %v", userID, err)
	}
	if userRecord.Status != status {
		t.Fatalf("user %d status = %q, want %q", userID, userRecord.Status, status)
	}
}

func assertTenantMembershipCount(t *testing.T, db *gorm.DB, tenantID int64, userIDs []int64, want int64) {
	t.Helper()

	var count int64
	if err := db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id IN ?", tenantID, userIDs).
		Count(&count).Error; err != nil {
		t.Fatalf("count tenant memberships: %v", err)
	}
	if count != want {
		t.Fatalf("tenant membership count = %d, want %d", count, want)
	}
}

func makeSystemUser(t *testing.T, db *gorm.DB, userID int64) {
	t.Helper()

	if err := user.NewService(db, audit.NoopRecorder{}).MarkSystemUser(t.Context(), userID, "root"); err != nil {
		t.Fatalf("MarkSystemUser() error = %v", err)
	}
}

func performJSON(t *testing.T, router http.Handler, method, target, body, accessToken string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var envelope struct {
		Success bool           `json:"success"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
	if !envelope.Success {
		t.Fatalf("success = false body=%s", recorder.Body.String())
	}
	return envelope.Data
}

func asSlice(t *testing.T, value any, name string) []any {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s = %#v, want slice", name, value)
	}
	return items
}

func asMap(t *testing.T, value any, name string) map[string]any {
	t.Helper()

	item, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", name, value)
	}
	return item
}

func findItemByStringField(t *testing.T, items []any, fieldName, want string) map[string]any {
	t.Helper()

	item := itemWithStringField(items, fieldName, want)
	if item != nil {
		return item
	}
	t.Fatalf("no item with %s = %q in %#v", fieldName, want, items)
	return nil
}

func itemWithStringField(items []any, fieldName, want string) map[string]any {
	for _, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if stringFromAny(record[fieldName]) == want {
			return record
		}
	}
	return nil
}

func stringFromAny(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func boolFromAny(value any) bool {
	if text, ok := value.(bool); ok {
		return text
	}
	return false
}

func numberFromAny(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case int64:
		return int(typed)
	default:
		return 0
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return privateKey
}

func totpCodeForTest(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}
	counter := uint64(at.Unix() / 30)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(message[:]); err != nil {
		t.Fatalf("write totp hmac: %v", err)
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", binaryCode%1000000)
}

func tenantIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}

func userIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}

func tinyPNG() []byte {
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
		0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41,
		0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
		0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
		0x42, 0x60, 0x82,
	}
}
