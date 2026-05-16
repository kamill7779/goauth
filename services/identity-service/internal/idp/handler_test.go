package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
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
		"POST /v1/external/github/exchange",
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

func TestCallbackCreatesExchangeCodeAndRedirectsToFrontend(t *testing.T) {
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
	store := newTestExchangeStore(t)
	handler := NewHandler(service, sessions, nil, false)
	handler.SetExchangeStore(store)
	handler.newState = func() (string, error) {
		return "expected-state", nil
	}

	router := gin.New()
	handler.RegisterRoutes(router)

	returnTo := "/oauth2/authorize?client_id=admin&response_type=code"
	startRecorder := httptest.NewRecorder()
	startRequest := httptest.NewRequest(http.MethodGet, "/v1/external/github/start?return_to="+url.QueryEscape(returnTo), nil)
	router.ServeHTTP(startRecorder, startRequest)
	if startRecorder.Code != http.StatusFound {
		t.Fatalf("start status = %d, want %d body=%s", startRecorder.Code, http.StatusFound, startRecorder.Body.String())
	}

	callbackRecorder := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/v1/external/github/callback?code=oauth-code&state=expected-state", nil)
	for _, cookie := range startRecorder.Result().Cookies() {
		if cookie.Name == githubOAuthStateCookieName {
			callbackRequest.AddCookie(cookie)
		}
	}
	router.ServeHTTP(callbackRecorder, callbackRequest)

	if callbackRecorder.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want %d body=%s", callbackRecorder.Code, http.StatusFound, callbackRecorder.Body.String())
	}
	location := callbackRecorder.Header().Get("Location")
	if !strings.HasPrefix(location, "/external/callback#") {
		t.Fatalf("Location = %q, want frontend exchange callback", location)
	}
	if strings.Contains(location, "?code=") || strings.Contains(location, "?provider=") {
		t.Fatalf("Location = %q, exchange credentials must not be in query", location)
	}
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	if parsedLocation.RawQuery != "" {
		t.Fatalf("callback query = %q, want empty", parsedLocation.RawQuery)
	}
	fragment, err := url.ParseQuery(parsedLocation.Fragment)
	if err != nil {
		t.Fatalf("parse callback fragment: %v", err)
	}
	if got := fragment.Get("provider"); got != "github" {
		t.Fatalf("provider fragment = %q, want github", got)
	}
	code := fragment.Get("code")
	if code == "" {
		t.Fatalf("Location = %q, missing exchange code", location)
	}
	if strings.Contains(location, "access-token") || strings.Contains(location, "refresh-token") {
		t.Fatalf("callback leaked tokens in redirect: %s", location)
	}

	payload, err := store.Consume(context.Background(), code)
	if err != nil {
		t.Fatalf("consume exchange code: %v", err)
	}
	if payload.ReturnTo != returnTo {
		t.Fatalf("return_to = %q, want %q", payload.ReturnTo, returnTo)
	}
	if payload.Tokens.AccessToken != "access-token" || payload.Tokens.RefreshToken != "refresh-token" {
		t.Fatalf("exchange tokens = %+v, want issued browser tokens", payload.Tokens)
	}
}

func TestStartStoresTrustedAbsoluteReturnTo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := NewService(nil, &fakeProvider{
		slug:        "github",
		displayName: "GitHub",
	})
	store := newTestExchangeStore(t)
	handler := NewHandler(service, nil, nil, false)
	handler.SetExchangeStore(store)
	handler.SetTrustedReturnToOrigins("https://identity.example.com")
	handler.newState = func() (string, error) {
		return "trusted-state", nil
	}

	router := gin.New()
	handler.RegisterRoutes(router)

	rawReturnTo := "https://identity.example.com/oauth2/authorize?client_id=admin&state=opaque"
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/external/github/start?return_to="+url.QueryEscape(rawReturnTo), nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}

	payload, err := store.ConsumeOAuthState(context.Background(), "trusted-state")
	if err != nil {
		t.Fatalf("consume oauth state: %v", err)
	}
	if payload.ReturnTo != rawReturnTo {
		t.Fatalf("return_to = %q, want %q", payload.ReturnTo, rawReturnTo)
	}
}

func TestExchangeRouteConsumesCodeOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newTestExchangeStore(t)
	code, err := store.Save(context.Background(), ExchangePayload{
		Provider: "github",
		Tokens: session.TokenPair{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			SessionID:    "browser-session",
		},
		User: ExchangeUser{
			ID:    44,
			Email: "octocat@example.com",
		},
		ReturnTo: "/admin",
	})
	if err != nil {
		t.Fatalf("save exchange payload: %v", err)
	}

	handler := NewHandler(nil, nil, nil, false)
	handler.SetExchangeStore(store)
	router := gin.New()
	handler.RegisterRoutes(router)

	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/external/github/exchange", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "access-token") || !strings.Contains(recorder.Body.String(), "/admin") {
		t.Fatalf("exchange response missing saved payload: %s", recorder.Body.String())
	}

	secondRecorder := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodPost, "/v1/external/github/exchange", bytes.NewReader(body))
	secondRequest.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(secondRecorder, secondRequest)
	if secondRecorder.Code != http.StatusBadRequest {
		t.Fatalf("second status = %d, want %d body=%s", secondRecorder.Code, http.StatusBadRequest, secondRecorder.Body.String())
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

func newTestExchangeStore(t *testing.T) *ExchangeStore {
	t.Helper()

	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	return NewExchangeStore(client)
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

func TestCallbackRejectsBrowserLoginWhenExchangeStoreUnavailable(t *testing.T) {
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

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "access-token") || strings.Contains(recorder.Body.String(), "refresh-token") {
		t.Fatalf("callback leaked tokens without exchange store: %s", recorder.Body.String())
	}
}
