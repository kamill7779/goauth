package idp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/session"
)

type fakeBrowserSessionManager struct {
	pair        *session.TokenPair
	cookieValue string
	ttl         time.Duration
}

func (f *fakeBrowserSessionManager) IssueTokens(context.Context, session.IssueTokensInput) (*session.TokenPair, error) {
	return f.pair, nil
}

func (f *fakeBrowserSessionManager) IssueOIDCAuthorizeCookieBySessionID(context.Context, string) (string, error) {
	return f.cookieValue, nil
}

func (f *fakeBrowserSessionManager) OIDCAuthorizeCookieTTL() time.Duration {
	return f.ttl
}

func TestRegisterRoutesRegistersGitHubEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	NewHandler(nil, nil, nil, true).RegisterRoutes(router)

	routes := map[string]bool{}
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	expected := []string{
		"GET /v1/external/github/start",
		"GET /v1/external/github/callback",
		"POST /v1/external/github/bind",
		"DELETE /v1/external/github/bind",
		"GET /v1/me/identities",
	}
	for _, route := range expected {
		if !routes[route] {
			t.Fatalf("missing route %s", route)
		}
	}
}

func TestStartSetsStateCookieAndRedirectsWithGeneratedState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := NewService(nil, &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
	})
	handler := NewHandler(service, nil, nil, true)
	handler.newState = func() (string, error) {
		return "generated-state", nil
	}

	router := gin.New()
	handler.RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/external/github/start?redirect_uri="+url.QueryEscape("https://app.example.com/callback"), nil)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}
	location, err := recorder.Result().Location()
	if err != nil {
		t.Fatalf("Location() error = %v", err)
	}
	if got := location.Query().Get("state"); got != "generated-state" {
		t.Fatalf("redirect state = %q, want generated-state", got)
	}

	found := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name != githubOAuthStateCookieName {
			continue
		}
		found = true
		if cookie.Value != "generated-state" {
			t.Fatalf("state cookie = %q, want generated-state", cookie.Value)
		}
		if !cookie.HttpOnly {
			t.Fatal("expected state cookie to be httpOnly")
		}
	}
	if !found {
		t.Fatalf("expected %s cookie to be set", githubOAuthStateCookieName)
	}
}

func TestStartUsesConfiguredInsecureStateCookieForLocalHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := NewService(nil, &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
	})
	handler := NewHandler(service, nil, nil, false)
	handler.newState = func() (string, error) {
		return "local-http-state", nil
	}

	router := gin.New()
	handler.RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/external/github/start", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name != githubOAuthStateCookieName {
			continue
		}
		if cookie.Secure {
			t.Fatal("expected local http state cookie to be insecure")
		}
		return
	}
	t.Fatalf("expected %s cookie to be set", githubOAuthStateCookieName)
}

func TestCallbackRejectsMissingOrMismatchedState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(NewService(nil), nil, nil, false)
	router := gin.New()
	handler.RegisterRoutes(router)

	t.Run("missing state", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/external/github/callback?code=oauth-code", nil)
		request.AddCookie(&http.Cookie{
			Name:  githubOAuthStateCookieName,
			Value: "expected-state",
		})

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
	})

	t.Run("mismatched state", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/external/github/callback?code=oauth-code&state=wrong-state", nil)
		request.AddCookie(&http.Cookie{
			Name:  githubOAuthStateCookieName,
			Value: "expected-state",
		})

		router.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
	})
}

func TestCallbackSetsOIDCAuthorizeCookieWhenSessionsAvailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	provider := &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
		token:       &TokenSet{AccessToken: "token-123"},
		profile: &ExternalProfile{
			Provider:       "github",
			ProviderUserID: "42",
			Email:          "octocat@example.com",
			EmailVerified:  true,
			Username:       "octocat",
			DisplayName:    "The Octocat",
		},
	}
	service := newTestService(t, provider)
	sessions := &fakeBrowserSessionManager{
		pair: &session.TokenPair{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			SessionID:    "browser-session",
		},
		cookieValue: "oidc-cookie-value",
		ttl:         12 * time.Hour,
	}
	handler := NewHandler(service, sessions, nil, false)

	router := gin.New()
	handler.RegisterRoutes(router)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/external/github/callback?code=oauth-code&state=expected-state", nil)
	request.AddCookie(&http.Cookie{
		Name:  githubOAuthStateCookieName,
		Value: "expected-state",
	})

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	stateCleared := false
	oidcCookieSet := false
	for _, header := range recorder.Header().Values("Set-Cookie") {
		if strings.HasPrefix(header, githubOAuthStateCookieName+"=;") {
			stateCleared = true
			break
		}
	}
	for _, cookie := range recorder.Result().Cookies() {
		switch cookie.Name {
		case session.OIDCAuthorizeCookieName:
			oidcCookieSet = true
			if cookie.Value != "oidc-cookie-value" {
				t.Fatalf("oidc cookie value = %q, want oidc-cookie-value", cookie.Value)
			}
			if cookie.Secure {
				t.Fatal("expected local browser oidc cookie to be insecure")
			}
			if !cookie.HttpOnly {
				t.Fatal("expected oidc cookie to be httpOnly")
			}
		}
	}
	if !stateCleared {
		t.Fatal("expected github oauth state cookie to be cleared")
	}
	if !oidcCookieSet {
		t.Fatal("expected oidc authorize cookie to be set")
	}
}
