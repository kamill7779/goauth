package session

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMeRouteReturnsClaimsForValidBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair, err := service.IssueTokens(t.Context(), IssueTokensInput{
		User:     *user,
		TenantID: 7,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	router := gin.New()
	NewHandler(service, &service.privateKey.PublicKey).RegisterRoutes(router.Group("/v1/auth"))

	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var payload struct {
		Success bool `json:"success"`
		Data    struct {
			UserID string `json:"user_id"`
			Email  string `json:"email"`
			Tenant int64  `json:"tid"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !payload.Success {
		t.Fatal("success = false, want true")
	}
	if payload.Data.UserID != "1" {
		t.Fatalf("user_id = %q, want 1", payload.Data.UserID)
	}
	if payload.Data.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.Data.Email, user.Email)
	}
	if payload.Data.Tenant != 7 {
		t.Fatalf("tenant = %d, want 7", payload.Data.Tenant)
	}
}

func TestMeRouteRejectsMissingBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _ := newTestService(t)
	router := gin.New()
	NewHandler(service, &service.privateKey.PublicKey).RegisterRoutes(router.Group("/v1/auth"))

	request := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestRefreshSetsOIDCAuthorizeCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, user := newTestService(t)
	pair, err := service.IssueTokens(t.Context(), IssueTokensInput{
		User:     *user,
		TenantID: 7,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	router := gin.New()
	NewHandler(service, &service.privateKey.PublicKey).RegisterRoutes(router.Group("/v1/auth"))

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(`{"refresh_token":"`+pair.RefreshToken+`"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	found := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == OIDCAuthorizeCookieName {
			found = true
			if cookie.Value == "" {
				t.Fatal("oidc authorize cookie is empty")
			}
		}
	}
	if !found {
		t.Fatal("expected oidc authorize cookie to be set")
	}
}
