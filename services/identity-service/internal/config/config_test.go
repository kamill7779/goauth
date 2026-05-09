package config

import (
	"testing"
	"time"
)

func TestLoadUsesDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("PUBLIC_ISSUER_URL", "")
	t.Setenv("MYSQL_DSN", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("BROWSER_SESSION_TTL", "")
	t.Setenv("REFRESH_TOKEN_TTL", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	t.Setenv("CORS_ALLOWED_METHODS", "")
	t.Setenv("CORS_ALLOWED_HEADERS", "")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.AppEnv != "development" {
		t.Fatalf("AppEnv = %q, want development", cfg.AppEnv)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.PublicIssuerURL != "http://127.0.0.1:8080" {
		t.Fatalf("PublicIssuerURL = %q, want default issuer", cfg.PublicIssuerURL)
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Fatalf("AccessTokenTTL = %v, want 15m", cfg.AccessTokenTTL)
	}
	if cfg.BrowserSessionTTL != 12*time.Hour {
		t.Fatalf("BrowserSessionTTL = %v, want 12h", cfg.BrowserSessionTTL)
	}
	if cfg.RefreshTokenTTL != 30*24*time.Hour {
		t.Fatalf("RefreshTokenTTL = %v, want 720h", cfg.RefreshTokenTTL)
	}
	if len(cfg.CORSAllowedMethods) != 5 {
		t.Fatalf("CORSAllowedMethods len = %d, want 5", len(cfg.CORSAllowedMethods))
	}
}

func TestLoadParsesTypedValues(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("PUBLIC_ISSUER_URL", "https://auth.example.com")
	t.Setenv("MYSQL_DSN", "root:root@tcp(localhost:3306)/goauth")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("ACCESS_TOKEN_TTL", "20m")
	t.Setenv("BROWSER_SESSION_TTL", "36h")
	t.Setenv("REFRESH_TOKEN_TTL", "48h")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com, https://admin.example.com")
	t.Setenv("CORS_ALLOWED_METHODS", "GET,POST")
	t.Setenv("CORS_ALLOWED_HEADERS", "Authorization, Content-Type")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "true")
	t.Setenv("GITHUB_OAUTH_ENABLED", "true")
	t.Setenv("GITHUB_CLIENT_ID", "client-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "client-secret")
	t.Setenv("GITHUB_REDIRECT_URI", "https://app.example.com/callback")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SMTPPort != 2525 {
		t.Fatalf("SMTPPort = %d, want 2525", cfg.SMTPPort)
	}
	if cfg.BrowserSessionTTL != 36*time.Hour {
		t.Fatalf("BrowserSessionTTL = %v, want 36h", cfg.BrowserSessionTTL)
	}
	if got, want := len(cfg.CORSAllowedOrigins), 2; got != want {
		t.Fatalf("len(CORSAllowedOrigins) = %d, want %d", got, want)
	}
	if !cfg.CORSAllowCredentials {
		t.Fatal("CORSAllowCredentials = false, want true")
	}
	if !cfg.GitHubOAuthEnabled {
		t.Fatal("GitHubOAuthEnabled = false, want true")
	}
	if cfg.GitHubRedirectURI != "https://app.example.com/callback" {
		t.Fatalf("GitHubRedirectURI = %q, want callback URI", cfg.GitHubRedirectURI)
	}
}
