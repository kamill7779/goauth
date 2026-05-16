package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadUsesDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("HTTP_ADDR", "")
	t.Setenv("PUBLIC_ISSUER_URL", "")
	t.Setenv("BROWSER_LOGIN_URL", "")
	t.Setenv("BROWSER_COOKIE_SECURE", "")
	t.Setenv("MYSQL_DSN", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("BROWSER_SESSION_TTL", "")
	t.Setenv("REFRESH_TOKEN_TTL", "")
	t.Setenv("TRUSTED_PROXIES", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	t.Setenv("CORS_ALLOWED_METHODS", "")
	t.Setenv("CORS_ALLOWED_HEADERS", "")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "")
	t.Setenv("DEFAULT_MEMBER_TENANT_SLUGS", "")

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
	if cfg.BrowserLoginURL != "/login" {
		t.Fatalf("BrowserLoginURL = %q, want /login", cfg.BrowserLoginURL)
	}
	if cfg.BrowserCookieSecure {
		t.Fatal("BrowserCookieSecure = true, want false for http default issuer")
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
	assertStringSlice(t, cfg.CORSAllowedHeaders, []string{"Authorization", "Content-Type", "X-Captcha-Token"})
	if cfg.CORSAllowCredentials {
		t.Fatal("CORSAllowCredentials = true, want false when no origins are configured")
	}
	if cfg.TrustedProxies != nil {
		t.Fatalf("TrustedProxies = %v, want nil by default", cfg.TrustedProxies)
	}
	if cfg.DefaultMemberTenantSlugs != nil {
		t.Fatalf("DefaultMemberTenantSlugs = %v, want nil by default", cfg.DefaultMemberTenantSlugs)
	}
}

func TestLoadAuthEntryDefaults(t *testing.T) {
	resetConfigEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.RegistrationMode != "open" {
		t.Fatalf("RegistrationMode = %q, want open", cfg.RegistrationMode)
	}
	if !cfg.LocalPasswordLoginEnabled {
		t.Fatal("LocalPasswordLoginEnabled = false, want true")
	}
	if cfg.MailerProvider != "console" {
		t.Fatalf("MailerProvider = %q, want console", cfg.MailerProvider)
	}
	if cfg.BrandName != "GoAuth" || cfg.BrandTagline != "" || cfg.BrandIconText != "G" || cfg.BrandIconURL != "" {
		t.Fatalf("brand defaults = %q/%q/%q/%q", cfg.BrandName, cfg.BrandTagline, cfg.BrandIconText, cfg.BrandIconURL)
	}
}

func TestLoadCaptchaActionsAndDefaultGitHubRedirect(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("PUBLIC_ISSUER_URL", "https://auth.example.com")
	t.Setenv("CAPTCHA_ACTIONS", "Login, REGISTER, email_code, Login")
	t.Setenv("GITHUB_OAUTH_ENABLED", "true")
	t.Setenv("GITHUB_CLIENT_ID", "client-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "secret")
	t.Setenv("GITHUB_REDIRECT_URI", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertStringSlice(t, cfg.CaptchaActions, []string{"login", "register", "email_code"})
	if cfg.GitHubRedirectURI != "https://auth.example.com/v1/external/github/callback" {
		t.Fatalf("GitHubRedirectURI = %q", cfg.GitHubRedirectURI)
	}
}

func TestLoadRejectsPartialCaptchaConfig(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("CAPTCHA_PROVIDER", "turnstile")
	t.Setenv("CAPTCHA_SITE_KEY", "site-key")
	t.Setenv("CAPTCHA_SECRET_KEY", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want error for partial CAPTCHA config")
	}
}

func TestLoadParsesTypedValues(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("PUBLIC_ISSUER_URL", "https://auth.example.com")
	t.Setenv("BROWSER_LOGIN_URL", "https://auth.example.com/login")
	t.Setenv("BROWSER_COOKIE_SECURE", "")
	t.Setenv("MYSQL_DSN", "root:root@tcp(localhost:3306)/goauth")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("ACCESS_TOKEN_TTL", "20m")
	t.Setenv("BROWSER_SESSION_TTL", "36h")
	t.Setenv("REFRESH_TOKEN_TTL", "48h")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.10")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_SSL", "true")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com, https://admin.example.com")
	t.Setenv("CORS_ALLOWED_METHODS", "GET,POST")
	t.Setenv("CORS_ALLOWED_HEADERS", "Authorization, Content-Type")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "true")
	t.Setenv("GITHUB_OAUTH_ENABLED", "true")
	t.Setenv("GITHUB_CLIENT_ID", "client-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "client-secret")
	t.Setenv("GITHUB_REDIRECT_URI", "https://app.example.com/callback")
	t.Setenv("DEFAULT_MEMBER_TENANT_SLUGS", " public-app, community , public-app ")
	t.Setenv("BRAND_NAME", "Acme ID")
	t.Setenv("BRAND_TAGLINE", "Secure workforce access")
	t.Setenv("BRAND_ICON_TEXT", "A")
	t.Setenv("BRAND_ICON_URL", "https://cdn.example.com/acme.svg")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SMTPPort != 2525 {
		t.Fatalf("SMTPPort = %d, want 2525", cfg.SMTPPort)
	}
	if !cfg.SMTPSSLEnabled {
		t.Fatal("SMTPSSLEnabled = false, want true")
	}
	if cfg.BrowserLoginURL != "https://auth.example.com/login" {
		t.Fatalf("BrowserLoginURL = %q, want configured URL", cfg.BrowserLoginURL)
	}
	if !cfg.BrowserCookieSecure {
		t.Fatal("BrowserCookieSecure = false, want true for https issuer")
	}
	if cfg.BrowserSessionTTL != 36*time.Hour {
		t.Fatalf("BrowserSessionTTL = %v, want 36h", cfg.BrowserSessionTTL)
	}
	if got, want := len(cfg.CORSAllowedOrigins), 2; got != want {
		t.Fatalf("len(CORSAllowedOrigins) = %d, want %d", got, want)
	}
	if got, want := len(cfg.TrustedProxies), 2; got != want {
		t.Fatalf("len(TrustedProxies) = %d, want %d", got, want)
	}
	if got := cfg.TrustedProxies[0]; got != "10.0.0.0/8" {
		t.Fatalf("TrustedProxies[0] = %q, want 10.0.0.0/8", got)
	}
	if got := cfg.TrustedProxies[1]; got != "192.168.1.10" {
		t.Fatalf("TrustedProxies[1] = %q, want 192.168.1.10", got)
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
	if got, want := len(cfg.DefaultMemberTenantSlugs), 2; got != want {
		t.Fatalf("len(DefaultMemberTenantSlugs) = %d, want %d", got, want)
	}
	if cfg.DefaultMemberTenantSlugs[0] != "public-app" || cfg.DefaultMemberTenantSlugs[1] != "community" {
		t.Fatalf("DefaultMemberTenantSlugs = %v, want [public-app community]", cfg.DefaultMemberTenantSlugs)
	}
	if cfg.BrandName != "Acme ID" || cfg.BrandTagline != "Secure workforce access" || cfg.BrandIconText != "A" || cfg.BrandIconURL != "https://cdn.example.com/acme.svg" {
		t.Fatalf("brand config = %q/%q/%q/%q", cfg.BrandName, cfg.BrandTagline, cfg.BrandIconText, cfg.BrandIconURL)
	}
}

func TestLoadDefaultsCORSCredentialsForExplicitOrigins(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://127.0.0.1:3000")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.CORSAllowCredentials {
		t.Fatal("CORSAllowCredentials = false, want true for explicit origins")
	}
}

func TestLoadKeepsWildcardCORSCredentialsDisabledByDefault(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("CORS_ALLOWED_ORIGINS", "*")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.CORSAllowCredentials {
		t.Fatal("CORSAllowCredentials = true, want false for wildcard origins")
	}
}

func TestLoadRejectsIncompleteProductionConfig(t *testing.T) {
	resetConfigEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("PUBLIC_ISSUER_URL", "http://auth.example.com")
	t.Setenv("MAILER_PROVIDER", "smtp")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want production validation error")
	}
	for _, fragment := range []string{
		"PUBLIC_ISSUER_URL",
		"MYSQL_DSN",
		"REDIS_URL",
		"JWT_PRIVATE_KEY_PATH",
		"JWT_KEY_ID",
		"SMTP_HOST",
		"SMTP_FROM",
	} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("Load() error %q missing %s", err.Error(), fragment)
		}
	}
}

func resetConfigEnv(t *testing.T) {
	t.Helper()

	keys := []string{
		"APP_ENV",
		"HTTP_ADDR",
		"PUBLIC_ISSUER_URL",
		"BROWSER_LOGIN_URL",
		"BROWSER_COOKIE_SECURE",
		"MYSQL_DSN",
		"REDIS_URL",
		"JWT_PRIVATE_KEY_PATH",
		"JWT_KEY_ID",
		"ACCESS_TOKEN_TTL",
		"BROWSER_SESSION_TTL",
		"REFRESH_TOKEN_TTL",
		"TRUSTED_PROXIES",
		"SMTP_HOST",
		"SMTP_PORT",
		"SMTP_USERNAME",
		"SMTP_PASSWORD",
		"SMTP_FROM",
		"SMTP_SSL",
		"SMTP_AUTH_LOGIN",
		"CORS_ALLOWED_ORIGINS",
		"CORS_ALLOWED_METHODS",
		"CORS_ALLOWED_HEADERS",
		"CORS_ALLOW_CREDENTIALS",
		"GITHUB_OAUTH_ENABLED",
		"GITHUB_CLIENT_ID",
		"GITHUB_CLIENT_SECRET",
		"GITHUB_REDIRECT_URI",
		"DEFAULT_MEMBER_TENANT_SLUGS",
		"BOOTSTRAP_ADMIN_EMAIL",
		"BOOTSTRAP_ADMIN_PASSWORD",
		"BOOTSTRAP_ADMIN_USERNAME",
		"BOOTSTRAP_ADMIN_NICKNAME",
		"BOOTSTRAP_ADMIN_DISPLAY_NAME",
		"BOOTSTRAP_ADMIN_ROLE",
		"LOCKOUT_THRESHOLD",
		"LOCKOUT_DURATION",
		"METRICS_ENABLED",
		"PASSWORD_MIN_LENGTH",
		"PASSWORD_REQUIRE_UPPERCASE",
		"PASSWORD_REQUIRE_LOWERCASE",
		"PASSWORD_REQUIRE_DIGIT",
		"PASSWORD_REQUIRE_SPECIAL",
		"PASSWORD_HISTORY_COUNT",
		"DEFAULT_LOCALE",
		"CAPTCHA_PROVIDER",
		"CAPTCHA_SECRET_KEY",
		"CAPTCHA_SITE_KEY",
		"CAPTCHA_ACTIONS",
		"REGISTRATION_MODE",
		"LOCAL_PASSWORD_LOGIN_ENABLED",
		"MAILER_PROVIDER",
		"BRAND_NAME",
		"BRAND_TAGLINE",
		"BRAND_ICON_TEXT",
		"BRAND_ICON_URL",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func assertStringSlice(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slice len = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slice[%d] = %q, want %q: %v", i, got[i], want[i], got)
		}
	}
}
