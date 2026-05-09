package session

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

func TestAuthMiddlewareRejectsDisabledUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair := issueSessionPair(t, service, *user, 0)
	router := newProtectedRouter(service)

	if err := service.db.Model(&store.User{}).Where("id = ?", user.ID).Update("status", store.UserStatusDisabled).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}

	assertProtectedStatus(t, router, pair.AccessToken, http.StatusUnauthorized)
}

func TestAuthMiddlewareRejectsStaleTokenVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair := issueSessionPair(t, service, *user, 0)
	router := newProtectedRouter(service)

	if err := service.db.Model(&store.User{}).Where("id = ?", user.ID).
		Update("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
		t.Fatalf("bump token version: %v", err)
	}

	assertProtectedStatus(t, router, pair.AccessToken, http.StatusUnauthorized)
}

func TestAuthMiddlewareRejectsLoggedOutSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair := issueSessionPair(t, service, *user, 0)
	router := newProtectedRouter(service)

	if err := service.Logout(t.Context(), pair.SessionID); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	assertProtectedStatus(t, router, pair.AccessToken, http.StatusUnauthorized)
}

func TestAuthMiddlewareRejectsLoggedOutAllSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair := issueSessionPair(t, service, *user, 0)
	router := newProtectedRouter(service)

	if err := service.LogoutAll(t.Context(), user.ID); err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}

	assertProtectedStatus(t, router, pair.AccessToken, http.StatusUnauthorized)
}

func TestAuthMiddlewareRejectsDisabledMembership(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	tenantRecord := store.Tenant{
		Name:   "Acme",
		Slug:   "acme",
		Status: store.TenantStatusActive,
	}
	if err := service.db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	member := store.TenantMember{
		TenantID: tenantRecord.ID,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	}
	if err := service.db.Create(&member).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	pair := issueSessionPair(t, service, *user, tenantRecord.ID)
	router := newProtectedRouter(service)

	if err := service.db.Model(&store.TenantMember{}).Where("id = ?", member.ID).
		Update("status", store.MemberStatusDisabled).Error; err != nil {
		t.Fatalf("disable member: %v", err)
	}

	assertProtectedStatus(t, router, pair.AccessToken, http.StatusUnauthorized)
}

func TestAuthMiddlewareRejectsOIDCAccessTokenClass(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair := issueSessionPair(t, service, *user, 0)
	router := newProtectedRouter(service)
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       strconv.FormatInt(user.ID, 10),
		"aud":       []string{"oidc-web"},
		"sid":       pair.SessionID,
		"ver":       user.TokenVersion,
		"token_use": "oidc_access",
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	raw, err := token.SignedString(service.privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	assertProtectedStatus(t, router, raw, http.StatusUnauthorized)
}

func TestSystemUserMiddlewareRejectsSystemRoleInDisabledTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	tenantRecord := store.Tenant{Name: "Admin Tenant", Slug: "admin-tenant", Status: store.TenantStatusActive}
	if err := service.db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	member := store.TenantMember{TenantID: tenantRecord.ID, UserID: user.ID, Status: store.MemberStatusActive}
	if err := service.db.Create(&member).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	role := store.Role{TenantID: tenantRecord.ID, Name: "System Admin", Code: "system-admin", IsSystem: true}
	if err := service.db.Create(&role).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := service.db.Create(&store.MemberRole{MemberID: member.ID, RoleID: role.ID}).Error; err != nil {
		t.Fatalf("create member role: %v", err)
	}

	pair := issueSessionPair(t, service, *user, 0)
	router := newSystemProtectedRouter(service)
	assertSystemProtectedStatus(t, router, pair.AccessToken, http.StatusOK)

	if err := service.db.Model(&store.Tenant{}).
		Where("id = ?", tenantRecord.ID).
		Update("status", store.TenantStatusDisabled).Error; err != nil {
		t.Fatalf("disable tenant: %v", err)
	}
	assertSystemProtectedStatus(t, router, pair.AccessToken, http.StatusForbidden)
}

func TestSystemUserMiddlewareRejectsRootEmailWithoutSystemRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	if err := service.db.Model(&store.User{}).Where("id = ?", user.ID).Update("email", "root@example.com").Error; err != nil {
		t.Fatalf("update email: %v", err)
	}
	pair := issueSessionPair(t, service, *user, 0)
	router := newSystemProtectedRouter(service)

	assertSystemProtectedStatus(t, router, pair.AccessToken, http.StatusForbidden)
}

func newProtectedRouter(service *Service) *gin.Engine {
	router := gin.New()
	router.GET("/protected", AuthMiddleware(service, &service.privateKey.PublicKey), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return router
}

func newSystemProtectedRouter(service *Service) *gin.Engine {
	router := gin.New()
	router.GET("/admin", AuthMiddleware(service, &service.privateKey.PublicKey), SystemUserMiddleware(service), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return router
}

func assertProtectedStatus(t *testing.T, router *gin.Engine, accessToken string, want int) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != want {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, want, recorder.Body.String())
	}
}

func assertSystemProtectedStatus(t *testing.T, router *gin.Engine, accessToken string, want int) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != want {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, want, recorder.Body.String())
	}
}
