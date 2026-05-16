// Package config loads service configuration from environment variables with
// sensible defaults. All settings are resolved at startup; runtime hot-reload
// is not supported.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultBrowserSessionTTL = 12 * time.Hour

type Config struct {
	AppEnv                    string
	HTTPAddr                  string
	PublicIssuerURL           string
	BrowserLoginURL           string
	BrowserCookieSecure       bool
	MySQLDSN                  string
	RedisURL                  string
	JWTPrivateKeyPath         string
	JWTKeyID                  string
	AccessTokenTTL            time.Duration
	BrowserSessionTTL         time.Duration
	RefreshTokenTTL           time.Duration
	TrustedProxies            []string
	SMTPHost                  string
	SMTPPort                  int
	SMTPUsername              string
	SMTPPassword              string
	SMTPFrom                  string
	SMTPSSLEnabled            bool
	SMTPAuthLogin             bool
	CORSAllowedOrigins        []string
	CORSAllowedMethods        []string
	CORSAllowedHeaders        []string
	CORSAllowCredentials      bool
	RegistrationMode          string
	LocalPasswordLoginEnabled bool
	MailerProvider            string
	BrandName                 string
	BrandTagline              string
	BrandIconText             string
	BrandIconURL              string
	GitHubOAuthEnabled        bool
	GitHubClientID            string
	GitHubClientSecret        string
	GitHubRedirectURI         string
	DefaultMemberTenantSlugs  []string
	BootstrapAdminEmail       string
	BootstrapAdminPassword    string
	BootstrapAdminUsername    string
	BootstrapAdminNickname    string
	BootstrapAdminDisplayName string
	BootstrapAdminRoleCode    string

	// Account lockout
	LockoutThreshold int64
	LockoutDuration  time.Duration

	// Observability
	MetricsEnabled bool

	// Password policy
	PasswordMinLength      int
	PasswordRequireUpper   bool
	PasswordRequireLower   bool
	PasswordRequireDigit   bool
	PasswordRequireSpecial bool
	PasswordHistoryCount   int

	// Email i18n
	DefaultLocale string

	// CAPTCHA
	CaptchaProvider  string
	CaptchaSecretKey string
	CaptchaSiteKey   string
	CaptchaActions   []string

	ConfiguredEnv map[string]bool `json:"-"`
}

// Load reads all configuration from environment variables. Missing variables
// fall back to safe defaults suitable for local development.
func Load() (Config, error) {
	accessTokenTTL, err := parseDurationEnv("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}

	browserSessionTTL, err := parseDurationEnv("BROWSER_SESSION_TTL", defaultBrowserSessionTTL)
	if err != nil {
		return Config{}, err
	}

	refreshTokenTTL, err := parseDurationEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	smtpPort, err := parseIntEnv("SMTP_PORT", 587)
	if err != nil {
		return Config{}, err
	}

	corsAllowedOrigins := splitCSV(envOrDefault("CORS_ALLOWED_ORIGINS", ""))
	corsAllowCredentials, err := parseBoolEnv("CORS_ALLOW_CREDENTIALS", defaultCORSAllowCredentials(corsAllowedOrigins))
	if err != nil {
		return Config{}, err
	}

	githubOAuthEnabled, err := parseBoolEnv("GITHUB_OAUTH_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	registrationMode := strings.ToLower(strings.TrimSpace(envOrDefault("REGISTRATION_MODE", "open")))
	if registrationMode != "open" && registrationMode != "invite_only" && registrationMode != "disabled" {
		return Config{}, fmt.Errorf("invalid REGISTRATION_MODE: %s", registrationMode)
	}
	localPasswordLoginEnabled, err := parseBoolEnv("LOCAL_PASSWORD_LOGIN_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	mailerProvider := strings.ToLower(strings.TrimSpace(envOrDefault("MAILER_PROVIDER", "console")))
	if mailerProvider != "console" && mailerProvider != "smtp" && mailerProvider != "noop" {
		return Config{}, fmt.Errorf("invalid MAILER_PROVIDER: %s", mailerProvider)
	}

	smtpSSLEnabled, err := parseBoolEnv("SMTP_SSL", false)
	if err != nil {
		return Config{}, err
	}
	smtpAuthLogin, err := parseBoolEnv("SMTP_AUTH_LOGIN", false)
	if err != nil {
		return Config{}, err
	}

	lockoutThreshold, err := parseInt64Env("LOCKOUT_THRESHOLD", 5)
	if err != nil {
		return Config{}, err
	}
	lockoutDuration, err := parseDurationEnv("LOCKOUT_DURATION", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	metricsEnabled, err := parseBoolEnv("METRICS_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	passwordMinLength, err := parseIntEnv("PASSWORD_MIN_LENGTH", 8)
	if err != nil {
		return Config{}, err
	}
	passwordRequireUpper, err := parseBoolEnv("PASSWORD_REQUIRE_UPPERCASE", false)
	if err != nil {
		return Config{}, err
	}
	passwordRequireLower, err := parseBoolEnv("PASSWORD_REQUIRE_LOWERCASE", false)
	if err != nil {
		return Config{}, err
	}
	passwordRequireDigit, err := parseBoolEnv("PASSWORD_REQUIRE_DIGIT", true)
	if err != nil {
		return Config{}, err
	}
	passwordRequireSpecial, err := parseBoolEnv("PASSWORD_REQUIRE_SPECIAL", false)
	if err != nil {
		return Config{}, err
	}
	passwordHistoryCount, err := parseIntEnv("PASSWORD_HISTORY_COUNT", 3)
	if err != nil {
		return Config{}, err
	}

	publicIssuerURL := envOrDefault("PUBLIC_ISSUER_URL", "http://127.0.0.1:8080")
	browserCookieSecure, err := parseBoolEnv("BROWSER_COOKIE_SECURE", strings.HasPrefix(strings.ToLower(publicIssuerURL), "https://"))
	if err != nil {
		return Config{}, err
	}
	githubRedirectURI := strings.TrimSpace(os.Getenv("GITHUB_REDIRECT_URI"))
	if githubOAuthEnabled && githubRedirectURI == "" {
		githubRedirectURI = strings.TrimRight(publicIssuerURL, "/") + "/v1/external/github/callback"
	}
	captchaProvider := strings.ToLower(strings.TrimSpace(os.Getenv("CAPTCHA_PROVIDER")))
	captchaSecretKey := os.Getenv("CAPTCHA_SECRET_KEY")
	captchaSiteKey := os.Getenv("CAPTCHA_SITE_KEY")
	if err := validateCaptchaConfig(captchaProvider, captchaSiteKey, captchaSecretKey); err != nil {
		return Config{}, err
	}

	cfg := Config{
		AppEnv:                    envOrDefault("APP_ENV", "development"),
		HTTPAddr:                  envOrDefault("HTTP_ADDR", ":8080"),
		PublicIssuerURL:           publicIssuerURL,
		BrowserLoginURL:           envOrDefault("BROWSER_LOGIN_URL", "/login"),
		BrowserCookieSecure:       browserCookieSecure,
		MySQLDSN:                  os.Getenv("MYSQL_DSN"),
		RedisURL:                  os.Getenv("REDIS_URL"),
		JWTPrivateKeyPath:         os.Getenv("JWT_PRIVATE_KEY_PATH"),
		JWTKeyID:                  os.Getenv("JWT_KEY_ID"),
		AccessTokenTTL:            accessTokenTTL,
		BrowserSessionTTL:         browserSessionTTL,
		RefreshTokenTTL:           refreshTokenTTL,
		TrustedProxies:            splitCSV(envOrDefault("TRUSTED_PROXIES", "")),
		SMTPHost:                  os.Getenv("SMTP_HOST"),
		SMTPPort:                  smtpPort,
		SMTPUsername:              os.Getenv("SMTP_USERNAME"),
		SMTPPassword:              os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:                  os.Getenv("SMTP_FROM"),
		SMTPSSLEnabled:            smtpSSLEnabled,
		SMTPAuthLogin:             smtpAuthLogin,
		CORSAllowedOrigins:        corsAllowedOrigins,
		CORSAllowedMethods:        splitCSV(envOrDefault("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE")),
		CORSAllowedHeaders:        splitCSV(envOrDefault("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-Captcha-Token")),
		CORSAllowCredentials:      corsAllowCredentials,
		RegistrationMode:          registrationMode,
		LocalPasswordLoginEnabled: localPasswordLoginEnabled,
		MailerProvider:            mailerProvider,
		BrandName:                 envOrDefault("BRAND_NAME", "GoAuth"),
		BrandTagline:              envOrDefault("BRAND_TAGLINE", ""),
		BrandIconText:             envOrDefault("BRAND_ICON_TEXT", "G"),
		BrandIconURL:              strings.TrimSpace(os.Getenv("BRAND_ICON_URL")),
		GitHubOAuthEnabled:        githubOAuthEnabled,
		GitHubClientID:            os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:        os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURI:         githubRedirectURI,
		DefaultMemberTenantSlugs:  splitUniqueCSV(os.Getenv("DEFAULT_MEMBER_TENANT_SLUGS")),
		BootstrapAdminEmail:       os.Getenv("BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPassword:    os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
		BootstrapAdminUsername:    os.Getenv("BOOTSTRAP_ADMIN_USERNAME"),
		BootstrapAdminNickname:    os.Getenv("BOOTSTRAP_ADMIN_NICKNAME"),
		BootstrapAdminDisplayName: os.Getenv("BOOTSTRAP_ADMIN_DISPLAY_NAME"),
		BootstrapAdminRoleCode:    envOrDefault("BOOTSTRAP_ADMIN_ROLE", "root"),

		LockoutThreshold: lockoutThreshold,
		LockoutDuration:  lockoutDuration,

		MetricsEnabled: metricsEnabled,

		PasswordMinLength:      passwordMinLength,
		PasswordRequireUpper:   passwordRequireUpper,
		PasswordRequireLower:   passwordRequireLower,
		PasswordRequireDigit:   passwordRequireDigit,
		PasswordRequireSpecial: passwordRequireSpecial,
		PasswordHistoryCount:   passwordHistoryCount,

		DefaultLocale: envOrDefault("DEFAULT_LOCALE", "en"),

		CaptchaProvider:  captchaProvider,
		CaptchaSecretKey: captchaSecretKey,
		CaptchaSiteKey:   captchaSiteKey,
		CaptchaActions:   splitUniqueLowerCSV(envOrDefault("CAPTCHA_ACTIONS", "login,register,email_code,password_forgot")),
		ConfiguredEnv:     configuredEnvKeys(),
	}
	if err := validateProductionConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateCaptchaConfig(provider, siteKey, secretKey string) error {
	provider = strings.TrimSpace(provider)
	siteKey = strings.TrimSpace(siteKey)
	secretKey = strings.TrimSpace(secretKey)
	if provider == "" && siteKey == "" && secretKey == "" {
		return nil
	}
	if provider == "" || siteKey == "" || secretKey == "" {
		return fmt.Errorf("CAPTCHA_PROVIDER, CAPTCHA_SITE_KEY, and CAPTCHA_SECRET_KEY must be set together")
	}
	switch provider {
	case "turnstile", "hcaptcha", "recaptcha":
		return nil
	default:
		return fmt.Errorf("invalid CAPTCHA_PROVIDER: %s", provider)
	}
}

func validateProductionConfig(cfg Config) error {
	if !strings.EqualFold(strings.TrimSpace(cfg.AppEnv), "production") {
		return nil
	}

	var issues []string
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.PublicIssuerURL)), "https://") {
		issues = append(issues, "PUBLIC_ISSUER_URL must use https in production")
	}
	if strings.TrimSpace(cfg.MySQLDSN) == "" {
		issues = append(issues, "MYSQL_DSN is required in production")
	}
	if strings.TrimSpace(cfg.RedisURL) == "" {
		issues = append(issues, "REDIS_URL is required in production")
	}
	if strings.TrimSpace(cfg.JWTPrivateKeyPath) == "" {
		issues = append(issues, "JWT_PRIVATE_KEY_PATH is required in production")
	}
	if strings.TrimSpace(cfg.JWTKeyID) == "" {
		issues = append(issues, "JWT_KEY_ID is required in production")
	}
	if cfg.MailerProvider == "smtp" {
		if strings.TrimSpace(cfg.SMTPHost) == "" {
			issues = append(issues, "SMTP_HOST is required when MAILER_PROVIDER=smtp")
		}
		if strings.TrimSpace(cfg.SMTPFrom) == "" {
			issues = append(issues, "SMTP_FROM is required when MAILER_PROVIDER=smtp")
		}
	}
	if len(issues) > 0 {
		return fmt.Errorf("invalid production config: %s", strings.Join(issues, "; "))
	}
	return nil
}

func (c Config) EnvConfigured(key string) (bool, bool) {
	if c.ConfiguredEnv == nil {
		return false, false
	}
	configured, ok := c.ConfiguredEnv[key]
	return configured, ok
}

func configuredEnvKeys() map[string]bool {
	result := make(map[string]bool, len(EnvDefinitions()))
	for _, definition := range EnvDefinitions() {
		value, ok := os.LookupEnv(definition.Name)
		result[definition.Name] = ok && strings.TrimSpace(value) != ""
	}
	return result
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func defaultCORSAllowCredentials(origins []string) bool {
	if len(origins) == 0 {
		return false
	}
	for _, origin := range origins {
		if strings.TrimSpace(origin) == "*" {
			return false
		}
	}
	return true
}

func parseDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}

func parseIntEnv(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}

func parseInt64Env(key string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}

func parseBoolEnv(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitUniqueCSV(value string) []string {
	parts := splitCSV(value)
	if len(parts) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result
}

func splitUniqueLowerCSV(value string) []string {
	parts := splitCSV(value)
	if len(parts) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(part)
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result
}
