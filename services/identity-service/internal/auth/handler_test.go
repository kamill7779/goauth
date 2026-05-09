package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/ratelimit"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
)

type failingAuditRecorder struct{}

func (failingAuditRecorder) Record(_ context.Context, _ audit.Entry) error {
	return errors.New("audit unavailable")
}

func browserLoginCSRFMaterial(t *testing.T, router *gin.Engine, returnTo string) (*http.Cookie, string) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/oauth2/login?return_to="+url.QueryEscape(returnTo), nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("browser login page status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var csrfCookie *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == browserLoginCSRFCookieName {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected browser login csrf cookie to be set")
	}
	if !strings.Contains(recorder.Body.String(), `name="csrf_token" value="`+csrfCookie.Value+`"`) {
		t.Fatalf("expected csrf token in rendered form body, got %s", recorder.Body.String())
	}
	return csrfCookie, csrfCookie.Value
}

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

func TestHostedBrowserLoginPageRendersSafeReturnTarget(t *testing.T) {
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

	router := gin.New()
	NewHandler(service, sessionService).RegisterBrowserRoutes(router)

	returnTo := "/oauth2/authorize?client_id=oidc-web&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"
	request := httptest.NewRequest(http.MethodGet, "/oauth2/login?return_to="+url.QueryEscape(returnTo), nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `<form method="post" action="/oauth2/login"`) {
		t.Fatalf("expected login form in body, got %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `name="return_to"`) {
		t.Fatalf("expected hidden return_to field in body, got %s", recorder.Body.String())
	}
	var csrfCookie *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == browserLoginCSRFCookieName {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected browser login csrf cookie to be set")
	}
	if !csrfCookie.HttpOnly {
		t.Fatal("expected browser login csrf cookie to be httpOnly")
	}
	if !csrfCookie.Secure {
		t.Fatal("expected browser login csrf cookie to be secure")
	}
	if !strings.Contains(recorder.Body.String(), `value="/oauth2/authorize?client_id=oidc-web&amp;redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"`) {
		t.Fatalf("expected safe return_to in body, got %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `name="csrf_token" value="`+csrfCookie.Value+`"`) {
		t.Fatalf("expected csrf token in body, got %s", recorder.Body.String())
	}
}

func TestHostedBrowserLoginRedirectsToAuthorizeAndSetsOIDCAuthorizeCookie(t *testing.T) {
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
		Email:           "browser-login@example.com",
		DisplayName:     "Browser Login",
		PasswordHash:    hash,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	router := gin.New()
	NewHandler(service, sessionService).RegisterBrowserRoutes(router)

	returnTo := "/oauth2/authorize?response_type=code&client_id=oidc-web&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&code_challenge=test&code_challenge_method=plain"
	csrfCookie, csrfToken := browserLoginCSRFMaterial(t, router, returnTo)
	form := url.Values{
		"email":      {user.Email},
		"password":   {"p@ssw0rd!"},
		"return_to":  {returnTo},
		"csrf_token": {csrfToken},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != returnTo {
		t.Fatalf("location = %q, want %q", location, returnTo)
	}

	found := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == session.OIDCAuthorizeCookieName {
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

func TestHostedBrowserLoginRejectsUnsafeReturnTarget(t *testing.T) {
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

	router := gin.New()
	NewHandler(service, sessionService).RegisterBrowserRoutes(router)

	form := url.Values{
		"email":     {"user@example.com"},
		"password":  {"p@ssw0rd!"},
		"return_to": {"https://evil.example.com/callback"},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestHostedBrowserLoginRejectsMissingCSRFCookie(t *testing.T) {
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

	router := gin.New()
	NewHandler(service, sessionService).RegisterBrowserRoutes(router)

	returnTo := "/oauth2/authorize?response_type=code&client_id=oidc-web&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&code_challenge=test&code_challenge_method=plain"
	form := url.Values{
		"email":      {"user@example.com"},
		"password":   {"p@ssw0rd!"},
		"return_to":  {returnTo},
		"csrf_token": {"token-without-cookie"},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid csrf token") {
		t.Fatalf("expected invalid csrf token message, got %s", recorder.Body.String())
	}
}

func TestHostedBrowserLoginRejectsMismatchedCSRFCookie(t *testing.T) {
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

	router := gin.New()
	NewHandler(service, sessionService).RegisterBrowserRoutes(router)

	returnTo := "/oauth2/authorize?response_type=code&client_id=oidc-web&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&code_challenge=test&code_challenge_method=plain"
	csrfCookie, _ := browserLoginCSRFMaterial(t, router, returnTo)
	form := url.Values{
		"email":      {"user@example.com"},
		"password":   {"p@ssw0rd!"},
		"return_to":  {returnTo},
		"csrf_token": {"different-token"},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid csrf token") {
		t.Fatalf("expected invalid csrf token message, got %s", recorder.Body.String())
	}
}

func TestLoginReturnsServerErrorWhenPostAuthWorkFails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	service.SetAuditRecorder(failingAuditRecorder{})

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
		Email:           "audit-failure@example.com",
		DisplayName:     "Audit Failure",
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

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "login unavailable") {
		t.Fatalf("expected generic login unavailable error, got %s", recorder.Body.String())
	}
}

func TestHostedBrowserLoginReturnsServerErrorWhenPostAuthWorkFails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	service.SetAuditRecorder(failingAuditRecorder{})

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
		Email:           "browser-audit-failure@example.com",
		DisplayName:     "Browser Audit Failure",
		PasswordHash:    hash,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	router := gin.New()
	NewHandler(service, sessionService).RegisterBrowserRoutes(router)

	returnTo := "/oauth2/authorize?response_type=code&client_id=oidc-web&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid&code_challenge=test&code_challenge_method=plain"
	csrfCookie, csrfToken := browserLoginCSRFMaterial(t, router, returnTo)
	form := url.Values{
		"email":      {user.Email},
		"password":   {"p@ssw0rd!"},
		"return_to":  {returnTo},
		"csrf_token": {csrfToken},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "login unavailable") {
		t.Fatalf("expected generic login unavailable error, got %s", recorder.Body.String())
	}
}

func TestLoginRateLimitReturnsTooManyRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetRateLimiter(ratelimit.NewService(service.redis))

	router := gin.New()
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    "missing@example.com",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for i := 0; i < loginRateLimitLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
	if !strings.Contains(recorder.Body.String(), "rate_limited") {
		t.Fatalf("expected rate_limited error, got %s", recorder.Body.String())
	}
}

func TestLoginRateLimitIgnoresSpoofedForwardedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetRateLimiter(ratelimit.NewService(service.redis))

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil) error = %v", err)
	}
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    "missing@example.com",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for i := 0; i < loginRateLimitLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		request.RemoteAddr = "10.0.0.8:12345"
		request.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(i+1))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
}

func TestLoginRateLimitUsesTrustedForwardedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetRateLimiter(ratelimit.NewService(service.redis))

	router := gin.New()
	if err := router.SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxies(...) error = %v", err)
	}
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    "missing@example.com",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for i := 0; i < loginRateLimitLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		request.RemoteAddr = "10.0.0.8:12345"
		request.Header.Set("X-Forwarded-For", "203.0.113.50")
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.50")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
}
