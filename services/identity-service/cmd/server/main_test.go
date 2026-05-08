package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
)

func TestBuildRouterSkipsGitHubIDPRoutesWhenDisabled(t *testing.T) {
	router := newTestRouter(t, config.Config{
		GitHubOAuthEnabled: false,
		GitHubClientID:     "client-id",
		GitHubClientSecret: "client-secret",
		GitHubRedirectURI:  "https://app.example.com/auth/github/callback",
	})

	assertGitHubRoutesRegistered(t, router, false)
}

func TestBuildRouterSkipsGitHubIDPRoutesWhenConfigIncomplete(t *testing.T) {
	testCases := []struct {
		name string
		cfg  config.Config
	}{
		{
			name: "missing client id",
			cfg: config.Config{
				GitHubOAuthEnabled: true,
				GitHubClientSecret: "client-secret",
				GitHubRedirectURI:  "https://app.example.com/auth/github/callback",
			},
		},
		{
			name: "missing client secret",
			cfg: config.Config{
				GitHubOAuthEnabled: true,
				GitHubClientID:     "client-id",
				GitHubRedirectURI:  "https://app.example.com/auth/github/callback",
			},
		},
		{
			name: "missing redirect uri",
			cfg: config.Config{
				GitHubOAuthEnabled: true,
				GitHubClientID:     "client-id",
				GitHubClientSecret: "client-secret",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			router := newTestRouter(t, testCase.cfg)
			assertGitHubRoutesRegistered(t, router, false)
		})
	}
}

func TestBuildRouterRegistersGitHubIDPRoutesWhenEnabledWithCompleteConfig(t *testing.T) {
	router := newTestRouter(t, config.Config{
		GitHubOAuthEnabled: true,
		GitHubClientID:     "client-id",
		GitHubClientSecret: "client-secret",
		GitHubRedirectURI:  "https://app.example.com/auth/github/callback",
	})

	assertGitHubRoutesRegistered(t, router, true)
}

func newTestRouter(t *testing.T, cfg config.Config) *gin.Engine {
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

	return buildRouter(cfg, db, nil, privateKey)
}

func assertGitHubRoutesRegistered(t *testing.T, router *gin.Engine, want bool) {
	t.Helper()

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
		if got := routes[route]; got != want {
			t.Fatalf("route %s registered = %v, want %v", route, got, want)
		}
	}
}
