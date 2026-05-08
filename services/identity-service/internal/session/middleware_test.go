package session

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
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

func newProtectedRouter(service *Service) *gin.Engine {
	router := gin.New()
	router.GET("/protected", AuthMiddleware(service, &service.privateKey.PublicKey), func(c *gin.Context) {
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
