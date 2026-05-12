package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/oidc"
	"goauth/services/identity-service/internal/rbac"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
	"goauth/services/identity-service/internal/user"
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

func TestRequireRedisFailsWhenUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}

	_, err = requireRedis(config.Config{RedisURL: "redis://" + addr + "/0"})
	if err == nil {
		t.Fatal("requireRedis() error = nil, want redis startup failure")
	}
	if !strings.Contains(err.Error(), "redis is required") {
		t.Fatalf("error = %v, want redis is required", err)
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

	for index, item := range items {
		record := asMap(t, item, "items["+strconv.Itoa(index)+"]")
		if stringFromAny(record[fieldName]) == want {
			return record
		}
	}
	t.Fatalf("no item with %s = %q in %#v", fieldName, want, items)
	return nil
}

func stringFromAny(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
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

func tenantIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}

func userIDString(id int64) string {
	return strconv.FormatInt(id, 10)
}
