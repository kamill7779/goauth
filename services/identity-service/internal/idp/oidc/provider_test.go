package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	idppkg "goauth/services/identity-service/internal/idp"
	oidcprovider "goauth/services/identity-service/internal/idp/oidc"
)

func mockDiscoveryServer(t *testing.T) *httptest.Server {
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

	srv = httptest.NewServer(mux)
	return srv
}

func TestNew_FetchesDiscovery(t *testing.T) {
	srv := mockDiscoveryServer(t)
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
	srv := mockDiscoveryServer(t)
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
