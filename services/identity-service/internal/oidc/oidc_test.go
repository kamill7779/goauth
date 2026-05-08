package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/session"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func TestDiscoveryDocumentIncludesRequiredEndpoints(t *testing.T) {
	_, router, _, _, _, _ := newTestProvider(t)

	request := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserInfoEndpoint      string `json:"userinfo_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if payload.Issuer != "https://identity.example.com" {
		t.Fatalf("issuer = %q, want https://identity.example.com", payload.Issuer)
	}
	if payload.AuthorizationEndpoint != "https://identity.example.com/oauth2/authorize" {
		t.Fatalf("authorization_endpoint = %q", payload.AuthorizationEndpoint)
	}
	if payload.TokenEndpoint != "https://identity.example.com/oauth2/token" {
		t.Fatalf("token_endpoint = %q", payload.TokenEndpoint)
	}
	if payload.UserInfoEndpoint != "https://identity.example.com/oauth2/userinfo" {
		t.Fatalf("userinfo_endpoint = %q", payload.UserInfoEndpoint)
	}
	if payload.JWKSURI != "https://identity.example.com/oauth2/jwks" {
		t.Fatalf("jwks_uri = %q", payload.JWKSURI)
	}
}

func TestAuthorizeValidatesClientAndRedirectURI(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)

	t.Run("unknown client", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=missing&redirect_uri=https://client.example.com/callback&scope=openid", nil)
		request.AddCookie(authorizeCookie)

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
		}
		assertJSONError(t, recorder.Body.Bytes(), "invalid_client")
	})

	t.Run("invalid redirect uri", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+client.ClientID+"&redirect_uri=https://evil.example.com/callback&scope=openid", nil)
		request.AddCookie(authorizeCookie)

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
		}
		assertJSONError(t, recorder.Body.Bytes(), "invalid_request")
	})
}

func TestAuthorizeRejectsMissingAuthenticatedSession(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)

	t.Run("missing cookie", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+client.ClientID+"&redirect_uri="+url.QueryEscape("https://client.example.com/callback")+"&scope=openid&code_challenge=test&code_challenge_method=plain", nil)

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
		assertJSONError(t, recorder.Body.Bytes(), "login_required")
	})

	t.Run("bearer token is not accepted", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+client.ClientID+"&redirect_uri="+url.QueryEscape("https://client.example.com/callback")+"&scope=openid&code_challenge=test&code_challenge_method=plain", nil)
		request.Header.Set("Authorization", issueSessionAuthorization(t, db, privateKey, *user))

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
		assertJSONError(t, recorder.Body.Bytes(), "login_required")
	})

	t.Run("revoked oidc session cookie is not accepted", func(t *testing.T) {
		authorizeCookie, sessionID := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
		now := time.Now().UTC()
		if err := db.Model(&store.RefreshToken{}).
			Where("session_id = ?", sessionID).
			Update("revoked_at", now).Error; err != nil {
			t.Fatalf("revoke refresh tokens: %v", err)
		}

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+client.ClientID+"&redirect_uri="+url.QueryEscape("https://client.example.com/callback")+"&scope=openid&code_challenge=test&code_challenge_method=plain", nil)
		request.AddCookie(authorizeCookie)

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
		assertJSONError(t, recorder.Body.Bytes(), "login_required")
	})
}

func TestAuthorizeRejectsUserWithoutTenantMembership(t *testing.T) {
	service, router, db, privateKey, user, _ := newTestProvider(t)
	client := mustCreateClient(t, service, CreateClientInput{
		TenantID:                2,
		ClientID:                "tenant-2-client",
		ClientSecret:            "tenant-2-secret",
		Name:                    "Tenant 2 Client",
		RedirectURIs:            []string{"https://tenant2.example.com/callback"},
		AllowedScopes:           []string{"openid", "profile", "email"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+client.ClientID+"&redirect_uri="+url.QueryEscape("https://tenant2.example.com/callback")+"&scope=openid&code_challenge=test&code_challenge_method=plain", nil)
	request.AddCookie(authorizeCookie)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	assertJSONError(t, recorder.Body.Bytes(), "access_denied")
}

func TestAuthorizeStoresAuthorizationCodeHash(t *testing.T) {
	service, router, db, privateKey, user, client := newTestProvider(t)
	verifier := "test-verifier-1234567890"
	challenge := pkceChallengeS256(verifier)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+client.ClientID+"&redirect_uri="+url.QueryEscape("https://client.example.com/callback")+"&scope="+url.QueryEscape("openid profile email offline_access")+"&state=state-123&nonce=nonce-123&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	request.AddCookie(authorizeCookie)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusFound)
	}

	location, err := recorder.Result().Location()
	if err != nil {
		t.Fatalf("Location() error = %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code in redirect")
	}
	if location.Query().Get("state") != "state-123" {
		t.Fatalf("state = %q, want state-123", location.Query().Get("state"))
	}

	var record store.OAuthAuthorizationCode
	if err := db.First(&record).Error; err != nil {
		t.Fatalf("load authorization code: %v", err)
	}
	if record.CodeHash == code {
		t.Fatal("authorization code stored in plaintext")
	}
	if record.CodeHash != service.hashAuthorizationCode(code) {
		t.Fatalf("code hash = %q, want %q", record.CodeHash, service.hashAuthorizationCode(code))
	}
}

func TestTokenEndpointRejectsInvalidPKCEVerifier(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/callback", "openid profile email offline_access", pkceChallengeS256("good-verifier"), "nonce-pkce")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example.com/callback"},
		"client_id":     {client.ClientID},
		"client_secret": {"super-secret"},
		"code_verifier": {"bad-verifier"},
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	assertJSONError(t, recorder.Body.Bytes(), "invalid_grant")
}

func TestTokenEndpointRejectsCodeWhenTenantMembershipIsRevoked(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 0)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/callback", "openid profile email offline_access", pkceChallengeS256("tenant-verifier"), "nonce-tenant")

	if err := db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ?", client.TenantID, user.ID).
		Update("status", store.MemberStatusDisabled).Error; err != nil {
		t.Fatalf("disable tenant member: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example.com/callback"},
		"client_id":     {client.ClientID},
		"client_secret": {"super-secret"},
		"code_verifier": {"tenant-verifier"},
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertJSONError(t, recorder.Body.Bytes(), "invalid_grant")
}

func TestTokenEndpointReturnsIDAccessAndRefreshTokens(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/callback", "openid profile email offline_access", pkceChallengeS256("correct-verifier"), "nonce-token")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example.com/callback"},
		"client_id":     {client.ClientID},
		"client_secret": {"super-secret"},
		"code_verifier": {"correct-verifier"},
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.AccessToken == "" {
		t.Fatal("missing access token")
	}
	if payload.IDToken == "" {
		t.Fatal("missing id token")
	}
	if payload.RefreshToken == "" {
		t.Fatal("missing refresh token")
	}
	if payload.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", payload.TokenType)
	}
}

func TestUserInfoReturnsClaimsForValidAccessToken(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/callback", "openid profile email offline_access", pkceChallengeS256("userinfo-verifier"), "nonce-userinfo")
	tokenSet := exchangeCode(t, router, client.ClientID, "super-secret", code, "https://client.example.com/callback", "userinfo-verifier")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokenSet.AccessToken)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var payload struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Sub != strconv.FormatInt(user.ID, 10) {
		t.Fatalf("sub = %q, want %d", payload.Sub, user.ID)
	}
	if payload.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.Email, user.Email)
	}
	if !payload.EmailVerified {
		t.Fatal("email_verified = false, want true")
	}
	if payload.Name != user.DisplayName {
		t.Fatalf("name = %q, want %q", payload.Name, user.DisplayName)
	}
}

func TestIDTokenAndUserInfoRespectGrantedScope(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/callback", "openid", pkceChallengeS256("scope-verifier"), "nonce-scope")
	tokenSet := exchangeCode(t, router, client.ClientID, "super-secret", code, "https://client.example.com/callback", "scope-verifier")

	token, err := jwt.Parse(tokenSet.IDToken, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if _, ok := claims["email"]; ok {
		t.Fatalf("email claim present for openid-only token: %#v", claims)
	}
	if _, ok := claims["name"]; ok {
		t.Fatalf("name claim present for openid-only token: %#v", claims)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokenSet.AccessToken)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if _, ok := payload["email"]; ok {
		t.Fatalf("userinfo email present for openid-only scope: %#v", payload)
	}
	if _, ok := payload["name"]; ok {
		t.Fatalf("userinfo name present for openid-only scope: %#v", payload)
	}
	if payload["sub"] != strconv.FormatInt(user.ID, 10) {
		t.Fatalf("userinfo sub = %v, want %d", payload["sub"], user.ID)
	}
}

func TestRevokeRevokesRefreshToken(t *testing.T) {
	service, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/callback", "openid profile email offline_access", pkceChallengeS256("revoke-verifier"), "nonce-revoke")
	tokenSet := exchangeCode(t, router, client.ClientID, "super-secret", code, "https://client.example.com/callback", "revoke-verifier")

	form := url.Values{
		"token":           {tokenSet.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {client.ClientID},
		"client_secret":   {"super-secret"},
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var refreshToken store.RefreshToken
	if err := db.Where("token_hash = ?", service.hashToken(tokenSet.RefreshToken)).First(&refreshToken).Error; err != nil {
		t.Fatalf("load refresh token: %v", err)
	}
	if refreshToken.RevokedAt == nil {
		t.Fatal("expected refresh token to be revoked")
	}
}

func TestLogoutRejectsUnregisteredRedirectURI(t *testing.T) {
	_, router, _, _, _, client := newTestProvider(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/logout?client_id="+client.ClientID+"&post_logout_redirect_uri="+url.QueryEscape("https://evil.example.com/logout"), nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertJSONError(t, recorder.Body.Bytes(), "invalid_request")
}

func TestLogoutRevokesSessionAndClearsOIDCCookie(t *testing.T) {
	_, router, db, privateKey, user, client := newTestProvider(t)
	authorizeCookie, sessionID := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oauth2/logout?client_id="+client.ClientID+"&post_logout_redirect_uri="+url.QueryEscape("https://client.example.com/callback"), nil)
	request.AddCookie(authorizeCookie)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}
	location, err := recorder.Result().Location()
	if err != nil {
		t.Fatalf("Location() error = %v", err)
	}
	if location.String() != "https://client.example.com/callback" {
		t.Fatalf("redirect = %q, want https://client.example.com/callback", location.String())
	}

	foundCookie := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == session.OIDCAuthorizeCookieName {
			foundCookie = true
			if cookie.Value != "" {
				t.Fatalf("cookie value = %q, want empty", cookie.Value)
			}
		}
	}
	if !foundCookie {
		t.Fatal("expected oidc authorize cookie to be cleared")
	}

	var count int64
	if err := db.Model(&store.RefreshToken{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).
		Count(&count).Error; err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("active refresh token count = %d, want 0", count)
	}
}

func TestCreateClientRejectsUnsupportedTokenEndpointAuthMethod(t *testing.T) {
	service, _, _, _, _, _ := newTestProvider(t)

	_, err := service.CreateClient(context.Background(), CreateClientInput{
		TenantID:                1,
		ClientID:                "bad-client",
		ClientSecret:            "super-secret",
		Name:                    "Bad Client",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		AllowedScopes:           []string{"openid"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "private_key_jwt",
	})
	if err == nil {
		t.Fatal("expected unsupported token endpoint auth method to fail")
	}
}

func TestTokenEndpointRequiresConfiguredClientAuthenticationMethod(t *testing.T) {
	service, router, db, privateKey, user, _ := newTestProvider(t)
	client := mustCreateClient(t, service, CreateClientInput{
		TenantID:                1,
		ClientID:                "basic-client",
		ClientSecret:            "basic-secret",
		Name:                    "Basic Client",
		RedirectURIs:            []string{"https://client.example.com/basic"},
		AllowedScopes:           []string{"openid", "profile", "email"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/basic", "openid profile email", pkceChallengeS256("basic-verifier"), "nonce-basic")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://client.example.com/basic"},
		"client_id":     {client.ClientID},
		"client_secret": {"basic-secret"},
		"code_verifier": {"basic-verifier"},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	assertJSONError(t, recorder.Body.Bytes(), "invalid_client")

	t.Run("accepts case-insensitive basic auth scheme", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"https://client.example.com/basic"},
			"code_verifier": {"basic-verifier"},
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Authorization", basicAuthHeaderWithScheme("basic", client.ClientID, "basic-secret"))
		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
		}
	})
}

func TestIntrospectAndRevokeRequireConfiguredClientAuthenticationMethod(t *testing.T) {
	service, router, db, privateKey, user, _ := newTestProvider(t)
	client := mustCreateClient(t, service, CreateClientInput{
		TenantID:                1,
		ClientID:                "basic-client-2",
		ClientSecret:            "basic-secret-2",
		Name:                    "Basic Client 2",
		RedirectURIs:            []string{"https://client.example.com/basic-2"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, client.ClientID, "https://client.example.com/basic-2", "openid profile email offline_access", pkceChallengeS256("basic2-verifier"), "nonce-basic2")
	tokenSet := exchangeCodeBasic(t, router, client.ClientID, "basic-secret-2", code, "https://client.example.com/basic-2", "basic2-verifier")

	introspectForm := url.Values{
		"token":         {tokenSet.AccessToken},
		"client_id":     {client.ClientID},
		"client_secret": {"basic-secret-2"},
	}
	introspectRecorder := httptest.NewRecorder()
	introspectRequest := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(introspectForm.Encode()))
	introspectRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(introspectRecorder, introspectRequest)

	if introspectRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("introspect status = %d, want %d body=%s", introspectRecorder.Code, http.StatusUnauthorized, introspectRecorder.Body.String())
	}
	assertJSONError(t, introspectRecorder.Body.Bytes(), "invalid_client")

	revokeForm := url.Values{
		"token":         {tokenSet.RefreshToken},
		"client_id":     {client.ClientID},
		"client_secret": {"basic-secret-2"},
	}
	revokeRecorder := httptest.NewRecorder()
	revokeRequest := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(revokeForm.Encode()))
	revokeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(revokeRecorder, revokeRequest)

	if revokeRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoke status = %d, want %d body=%s", revokeRecorder.Code, http.StatusUnauthorized, revokeRecorder.Body.String())
	}
	assertJSONError(t, revokeRecorder.Body.Bytes(), "invalid_client")
}

func TestIntrospectRestrictsTokensToOwningClient(t *testing.T) {
	service, router, db, privateKey, user, clientA := newTestProvider(t)
	clientB := mustCreateClient(t, service, CreateClientInput{
		TenantID:                1,
		ClientID:                "oidc-other",
		ClientSecret:            "other-secret",
		Name:                    "OIDC Other",
		RedirectURIs:            []string{"https://other.example.com/callback"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_post",
	})

	authorizeCookie, _ := issueOIDCAuthorizeCookie(t, db, privateKey, *user, 1)
	code := authorizeCode(t, router, authorizeCookie, clientA.ClientID, "https://client.example.com/callback", "openid profile email offline_access", pkceChallengeS256("introspect-verifier"), "nonce-introspect")
	tokenSet := exchangeCode(t, router, clientA.ClientID, "super-secret", code, "https://client.example.com/callback", "introspect-verifier")

	for name, token := range map[string]string{
		"access token":  tokenSet.AccessToken,
		"refresh token": tokenSet.RefreshToken,
	} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{
				"token":         {token},
				"client_id":     {clientB.ClientID},
				"client_secret": {"other-secret"},
			}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
			}

			var payload struct {
				Active bool `json:"active"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("json.Unmarshal() error = %v", err)
			}
			if payload.Active {
				t.Fatal("expected token from another client to introspect as inactive")
			}
		})
	}
}

type exchangedTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func newTestProvider(t *testing.T) (*Service, *gin.Engine, *gorm.DB, *rsa.PrivateKey, *store.User, *store.OAuthClient) {
	t.Helper()

	gin.SetMode(gin.TestMode)

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

	service := NewService(db, config.Config{
		PublicIssuerURL: "https://identity.example.com",
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, privateKey)

	now := time.Now().UTC()
	user := &store.User{
		Email:           "oidc-user@example.com",
		DisplayName:     "OIDC User",
		PasswordHash:    "hash",
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("db.Create(user) error = %v", err)
	}
	if err := db.Create(&store.TenantMember{
		TenantID: 1,
		UserID:   user.ID,
		Status:   store.MemberStatusActive,
	}).Error; err != nil {
		t.Fatalf("db.Create(tenant member) error = %v", err)
	}

	client, err := service.CreateClient(context.Background(), CreateClientInput{
		TenantID:                1,
		ClientID:                "oidc-web",
		ClientSecret:            "super-secret",
		Name:                    "OIDC Web",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}

	router := gin.New()
	RegisterRoutes(router, service)
	return service, router, db, privateKey, user, client
}

func authorizeCode(t *testing.T, router http.Handler, authorizeCookie *http.Cookie, clientID, redirectURI, scope, challenge, nonce string) string {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id="+clientID+"&redirect_uri="+url.QueryEscape(redirectURI)+"&scope="+url.QueryEscape(scope)+"&state=test-state&nonce="+nonce+"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	request.AddCookie(authorizeCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want %d body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	location, err := recorder.Result().Location()
	if err != nil {
		t.Fatalf("Location() error = %v", err)
	}
	return location.Query().Get("code")
}

func exchangeCode(t *testing.T, router http.Handler, clientID, clientSecret, code, redirectURI, verifier string) exchangedTokens {
	t.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("token status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var payload exchangedTokens
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return payload
}

func exchangeCodeBasic(t *testing.T, router http.Handler, clientID, clientSecret, code, redirectURI, verifier string) exchangedTokens {
	t.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", basicAuthHeader(clientID, clientSecret))
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("token status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var payload exchangedTokens
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return payload
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func assertJSONError(t *testing.T, body []byte, want string) {
	t.Helper()

	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload.Error != want {
		t.Fatalf("error = %q, want %q", payload.Error, want)
	}
}

func issueSessionAuthorization(t *testing.T, db *gorm.DB, privateKey *rsa.PrivateKey, user store.User) string {
	t.Helper()

	sessionService := session.NewService(db, config.Config{
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, privateKey)
	pair, err := sessionService.IssueTokens(context.Background(), session.IssueTokensInput{
		User:     user,
		TenantID: 1,
		ClientID: "browser-session",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}
	return "Bearer " + pair.AccessToken
}

func issueOIDCAuthorizeCookie(t *testing.T, db *gorm.DB, privateKey *rsa.PrivateKey, user store.User, tenantID int64) (*http.Cookie, string) {
	t.Helper()

	sessionService := session.NewService(db, config.Config{
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, privateKey)
	pair, err := sessionService.IssueTokens(context.Background(), session.IssueTokensInput{
		User:     user,
		TenantID: tenantID,
		ClientID: "goauth-browser",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}
	value, err := sessionService.IssueOIDCAuthorizeCookie(user, tenantID, pair.SessionID)
	if err != nil {
		t.Fatalf("IssueOIDCAuthorizeCookie() error = %v", err)
	}
	return &http.Cookie{
		Name:   session.OIDCAuthorizeCookieName,
		Value:  value,
		Path:   "/",
		Secure: true,
	}, pair.SessionID
}

func mustCreateClient(t *testing.T, service *Service, input CreateClientInput) *store.OAuthClient {
	t.Helper()

	client, err := service.CreateClient(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	return client
}

func basicAuthHeader(clientID, clientSecret string) string {
	return basicAuthHeaderWithScheme("Basic", clientID, clientSecret)
}

func basicAuthHeaderWithScheme(scheme, clientID, clientSecret string) string {
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
}
