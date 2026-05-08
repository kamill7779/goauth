package idp

import (
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
