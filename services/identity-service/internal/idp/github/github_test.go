package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"example.com/identity-service/internal/idp"
)

func TestAuthCodeURLBuildsGitHubAuthorizeURL(t *testing.T) {
	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://app.example.com/auth/github/callback",
	})

	rawURL, err := provider.AuthCodeURL("state-123", idp.AuthCodeOptions{})
	if err != nil {
		t.Fatalf("AuthCodeURL() error = %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if parsed.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", parsed.Scheme)
	}
	if parsed.Host != "github.com" {
		t.Fatalf("host = %q, want github.com", parsed.Host)
	}
	if parsed.Path != "/login/oauth/authorize" {
		t.Fatalf("path = %q, want /login/oauth/authorize", parsed.Path)
	}

	query := parsed.Query()
	if query.Get("client_id") != "client-id" {
		t.Fatalf("client_id = %q, want client-id", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://app.example.com/auth/github/callback" {
		t.Fatalf("redirect_uri = %q, want configured redirect URI", query.Get("redirect_uri"))
	}
	if query.Get("scope") != "read:user user:email" {
		t.Fatalf("scope = %q, want read:user user:email", query.Get("scope"))
	}
	if query.Get("state") != "state-123" {
		t.Fatalf("state = %q, want state-123", query.Get("state"))
	}
}

func TestExchangeCodeUsesConfiguredRedirectURI(t *testing.T) {
	var redirectURI string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/oauth/access_token" {
			t.Fatalf("path = %q, want /login/oauth/access_token", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm() error = %v", err)
		}
		redirectURI = r.Form.Get("redirect_uri")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-123",
			"token_type":   "bearer",
			"scope":        "read:user,user:email",
		})
	}))
	defer server.Close()

	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://app.example.com/auth/github/callback",
		TokenURL:     server.URL + "/login/oauth/access_token",
		HTTPClient:   server.Client(),
	})

	token, err := provider.ExchangeCode(context.Background(), "oauth-code", "")
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	if token.AccessToken != "token-123" {
		t.Fatalf("token.AccessToken = %q, want token-123", token.AccessToken)
	}
	if redirectURI != "https://app.example.com/auth/github/callback" {
		t.Fatalf("redirect_uri = %q, want configured redirect URI", redirectURI)
	}
}

func TestFetchProfileLoadsUserAndEmails(t *testing.T) {
	var sawUser bool
	var sawEmails bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-123" {
			t.Fatalf("Authorization = %q, want Bearer token-123", r.Header.Get("Authorization"))
		}

		switch r.URL.Path {
		case "/user":
			sawUser = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         42,
				"login":      "octocat",
				"name":       "The Octocat",
				"avatar_url": "https://avatars.example.test/octocat.png",
				"email":      "octocat@example.com",
			})
		case "/user/emails":
			sawEmails = true
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"email":    "octocat@example.com",
					"primary":  true,
					"verified": true,
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://app.example.com/auth/github/callback",
		APIBaseURL:   server.URL,
		HTTPClient:   server.Client(),
	})

	profile, err := provider.FetchProfile(context.Background(), &idp.TokenSet{AccessToken: "token-123"})
	if err != nil {
		t.Fatalf("FetchProfile() error = %v", err)
	}
	if !sawUser || !sawEmails {
		t.Fatalf("sawUser = %v, sawEmails = %v, want both true", sawUser, sawEmails)
	}
	if profile.Provider != "github" {
		t.Fatalf("profile.Provider = %q, want github", profile.Provider)
	}
	if profile.ProviderUserID != "42" {
		t.Fatalf("profile.ProviderUserID = %q, want 42", profile.ProviderUserID)
	}
	if profile.Email != "octocat@example.com" {
		t.Fatalf("profile.Email = %q, want octocat@example.com", profile.Email)
	}
	if !profile.EmailVerified {
		t.Fatal("profile.EmailVerified = false, want true")
	}
}

func TestFetchProfileResolvesHiddenEmailFromPrimaryVerifiedEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         42,
				"login":      "octocat",
				"name":       "The Octocat",
				"avatar_url": "https://avatars.example.test/octocat.png",
				"email":      "",
			})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"email":    "secondary@example.com",
					"primary":  false,
					"verified": true,
				},
				{
					"email":    "primary@example.com",
					"primary":  true,
					"verified": true,
				},
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := New(Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURI:  "https://app.example.com/auth/github/callback",
		APIBaseURL:   server.URL,
		HTTPClient:   server.Client(),
	})

	profile, err := provider.FetchProfile(context.Background(), &idp.TokenSet{AccessToken: "token-123"})
	if err != nil {
		t.Fatalf("FetchProfile() error = %v", err)
	}
	if profile.Email != "primary@example.com" {
		t.Fatalf("profile.Email = %q, want primary@example.com", profile.Email)
	}
	if !profile.EmailVerified {
		t.Fatal("profile.EmailVerified = false, want true")
	}
}
