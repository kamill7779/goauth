package idp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisterRoutesRegistersGitHubEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	NewHandler(nil, nil, nil).RegisterRoutes(router)

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
	handler := NewHandler(service, nil, nil)
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

func TestCallbackRejectsMissingOrMismatchedState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(NewService(nil), nil, nil)
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
