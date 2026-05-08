package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
)

func TestBuildRouterRegistersOIDCRoutes(t *testing.T) {
	cfg := config.Config{
		PublicIssuerURL: "https://identity.example.com",
	}

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

	router := buildRouter(cfg, db, privateKey, nil)

	testCases := []struct {
		method string
		target string
	}{
		{method: http.MethodGet, target: "/.well-known/openid-configuration"},
		{method: http.MethodGet, target: "/oauth2/jwks"},
		{method: http.MethodGet, target: "/oauth2/authorize"},
		{method: http.MethodPost, target: "/oauth2/token"},
		{method: http.MethodGet, target: "/oauth2/userinfo"},
		{method: http.MethodPost, target: "/oauth2/introspect"},
		{method: http.MethodPost, target: "/oauth2/revoke"},
		{method: http.MethodGet, target: "/oauth2/logout"},
	}

	for _, tc := range testCases {
		request := httptest.NewRequest(tc.method, tc.target, nil)
		recorder := httptest.NewRecorder()

		router.ServeHTTP(recorder, request)

		if recorder.Code == http.StatusNotFound {
			t.Fatalf("%s %s returned 404, want registered route", tc.method, tc.target)
		}
	}
}
