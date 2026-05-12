package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	idppkg "goauth/services/identity-service/internal/idp"
	oidcprovider "goauth/services/identity-service/internal/idp/oidc"
)

func mockDiscoveryServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/oauth/authorize",
			"token_endpoint":         srv.URL + "/oauth/token",
			"userinfo_endpoint":      srv.URL + "/oauth/userinfo",
			"jwks_uri":               srv.URL + "/oauth/jwks",
		})
	})

	mux.HandleFunc("/oauth/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	})

	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if tokenHandler == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
			})
			return
		}
		tokenHandler(w, r)
	})

	srv = httptest.NewServer(mux)
	return srv
}

func TestNew_FetchesDiscovery(t *testing.T) {
	srv := mockDiscoveryServer(t, nil)
	defer srv.Close()

	cfg := oidcprovider.Config{
		Slug:         "test-oidc",
		DisplayName:  "Test OIDC",
		DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
		ClientID:     "client123",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example.com/callback",
	}

	p, err := oidcprovider.New(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Slug() != "test-oidc" {
		t.Errorf("expected slug 'test-oidc', got %q", p.Slug())
	}
	if p.DisplayName() != "Test OIDC" {
		t.Errorf("expected display name 'Test OIDC', got %q", p.DisplayName())
	}
}

func TestNew_FailsOnBadDiscoveryURL(t *testing.T) {
	cfg := oidcprovider.Config{
		Slug:         "bad",
		DiscoveryURL: "http://127.0.0.1:1/nonexistent",
		ClientID:     "x",
		ClientSecret: "y",
	}
	_, err := oidcprovider.New(cfg)
	if err == nil {
		t.Error("expected error for unreachable discovery URL")
	}
}

func TestNew_FailsOnEmptyDiscoveryURL(t *testing.T) {
	cfg := oidcprovider.Config{
		Slug:     "empty",
		ClientID: "x",
	}
	_, err := oidcprovider.New(cfg)
	if err == nil {
		t.Error("expected error for empty discovery URL")
	}
}

func TestAuthCodeURL_ContainsPKCE(t *testing.T) {
	srv := mockDiscoveryServer(t, nil)
	defer srv.Close()

	cfg := oidcprovider.Config{
		Slug:         "pkce-test",
		DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example.com/callback",
	}
	p, err := oidcprovider.New(cfg)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	authURL, err := p.AuthCodeURL("state123", idppkg.AuthCodeOptions{RedirectURI: "https://app.example.com/callback"})
	if err != nil {
		t.Fatalf("AuthCodeURL error: %v", err)
	}

	if !strings.Contains(authURL, "code_challenge=") {
		t.Errorf("expected code_challenge in URL: %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("expected code_challenge_method=S256 in URL: %s", authURL)
	}
	if !strings.Contains(authURL, "state=state123") {
		t.Errorf("expected state in URL: %s", authURL)
	}
}

func TestExchangeCode_SendsStoredPKCEVerifier(t *testing.T) {
	var capturedVerifier string
	srv := mockDiscoveryServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		capturedVerifier = r.Form.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
		})
	})
	defer srv.Close()

	cfg := oidcprovider.Config{
		Slug:         "pkce-test",
		DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example.com/callback",
	}
	p, err := oidcprovider.New(cfg)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	authURL, err := p.AuthCodeURL("state123", idppkg.AuthCodeOptions{RedirectURI: cfg.RedirectURI})
	if err != nil {
		t.Fatalf("AuthCodeURL() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if parsed.Query().Get("code_challenge") == "" {
		t.Fatal("expected code_challenge in authorization URL")
	}

	token, err := p.ExchangeCode(context.Background(), "oauth-code", cfg.RedirectURI, "state123")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	if token.AccessToken != "access-token" {
		t.Fatalf("token.AccessToken = %q, want access-token", token.AccessToken)
	}
	if capturedVerifier == "" {
		t.Fatal("expected token exchange to include code_verifier")
	}
}

func TestExchangeCode_RequiresStoredPKCEVerifier(t *testing.T) {
	srv := mockDiscoveryServer(t, nil)
	defer srv.Close()

	cfg := oidcprovider.Config{
		Slug:         "pkce-test",
		DiscoveryURL: srv.URL + "/.well-known/openid-configuration",
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURI:  "https://app.example.com/callback",
	}
	p, err := oidcprovider.New(cfg)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	if _, err := p.ExchangeCode(context.Background(), "oauth-code", cfg.RedirectURI, "missing-state"); err == nil {
		t.Fatal("expected missing PKCE verifier error")
	}
}
