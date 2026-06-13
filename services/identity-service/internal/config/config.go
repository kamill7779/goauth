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
	AvatarStorageDir          string
	JWTPrivateKeyPath         string
	JWTKeyID                  string
	JWTKeysetDir              string
	JWTActiveKeyID            string
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

// ── Sub-config types — extracted for dependency narrowing in Phase 3 ──

// TokenConfig groups JWT signing and token lifetime settings.
type TokenConfig struct {
	KeyID              string
	ActiveKeyID        string
	KeysetDir          string
	PrivateKeyPath     string
	AccessTokenTTL     time.Duration
	RefreshTokenTTL    time.Duration
	BrowserSessionTTL  time.Duration
	BrowserCookieSecure bool
}

// MailerConfig groups SMTP and email provider settings.
type MailerConfig struct {
	Provider string
	SMTP     SMTPConfig
	From     string
}

// SMTPConfig holds raw SMTP connection parameters.
type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	SSL       bool
	AuthLogin bool
}

// BrandConfig groups UI branding settings.
type BrandConfig struct {
	Name     string
	Tagline  string
	IconText string
	IconURL  string
}

// PasswordConfig groups password policy parameters.
type PasswordConfig struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSpecial bool
	HistoryCount   int
}

// LockoutConfig groups account lockout thresholds.
type LockoutConfig struct {
	Threshold int64
	Duration  time.Duration
}

// GitHubOAuthConfig groups GitHub OAuth provider settings.
type GitHubOAuthConfig struct {
	Enabled     bool
	ClientID    string
	ClientSecret string
	RedirectURI string
}

// Token returns the JWT signing and token-lifetime sub-config.
//
// Call chain: any service constructor → Config.Token → (no downstream)
func (c Config) Token() TokenConfig {
	return TokenConfig{
		KeyID:              c.JWTKeyID,
		ActiveKeyID:        c.JWTActiveKeyID,
		KeysetDir:          c.JWTKeysetDir,
		PrivateKeyPath:     c.JWTPrivateKeyPath,
		AccessTokenTTL:     c.AccessTokenTTL,
		RefreshTokenTTL:    c.RefreshTokenTTL,
		BrowserSessionTTL:  c.BrowserSessionTTL,
		BrowserCookieSecure: c.BrowserCookieSecure,
	}
}

// Mailer returns the mailer (SMTP/console/noop) sub-config.
//
// Call chain: main.registerRoutes → Config.Mailer → (no downstream)
func (c Config) Mailer() MailerConfig {
	return MailerConfig{
		Provider: c.MailerProvider,
		SMTP: SMTPConfig{
			Host:      c.SMTPHost,
			Port:      c.SMTPPort,
			Username:  c.SMTPUsername,
			Password:  c.SMTPPassword,
			SSL:       c.SMTPSSLEnabled,
			AuthLogin: c.SMTPAuthLogin,
		},
		From: c.SMTPFrom,
	}
}

// Brand returns the UI branding sub-config.
//
// Call chain: mailer/template rendering → Config.Brand → (no downstream)
func (c Config) Brand() BrandConfig {
	return BrandConfig{
		Name:     c.BrandName,
		Tagline:  c.BrandTagline,
		IconText: c.BrandIconText,
		IconURL:  c.BrandIconURL,
	}
}

// PasswordPolicy returns the password-complexity policy sub-config.
//
// Call chain: password.LoadFromConfig → Config.PasswordPolicy → (no downstream)
func (c Config) PasswordPolicy() PasswordConfig {
	return PasswordConfig{
		MinLength:      c.PasswordMinLength,
		RequireUpper:   c.PasswordRequireUpper,
		RequireLower:   c.PasswordRequireLower,
		RequireDigit:   c.PasswordRequireDigit,
		RequireSpecial: c.PasswordRequireSpecial,
		HistoryCount:   c.PasswordHistoryCount,
	}
}

// Lockout returns the account-lockout threshold and duration sub-config.
//
// Call chain: lockout.NewManager → Config.Lockout → (no downstream)
func (c Config) Lockout() LockoutConfig {
	return LockoutConfig{
		Threshold: c.LockoutThreshold,
		Duration:  c.LockoutDuration,
	}
}

// GitHubOAuth returns the GitHub OAuth provider sub-config.
//
// Call chain: main.buildServices → Config.GitHubOAuth → (no downstream)
func (c Config) GitHubOAuth() GitHubOAuthConfig {
	return GitHubOAuthConfig{
		Enabled:      c.GitHubOAuthEnabled,
		ClientID:     c.GitHubClientID,
		ClientSecret: c.GitHubClientSecret,
		RedirectURI:  c.GitHubRedirectURI,
	}
}

// IsGitHubConfigured reports whether every required GitHub OAuth field is populated,
// so callers can decide whether to register the GitHub IDP routes.
//
// Call chain: main.buildServices → Config.IsGitHubConfigured → (no downstream)
func (c Config) IsGitHubConfigured() bool {
	return c.GitHubOAuthEnabled &&
		c.GitHubClientID != "" &&
		c.GitHubClientSecret != "" &&
		c.GitHubRedirectURI != ""
}

// Load reads every recognised environment variable and returns a validated Config.
// Missing variables fall back to safe defaults; invalid values return an error.
// In production (APP_ENV=production) extra checks reject insecure settings.
//
// Call chain: main.run → config.Load → envOrDefault / parseDurationEnv / parseIntEnv / parseBoolEnv / splitCSV / validateCaptchaConfig / validateProductionConfig / configuredEnvKeys
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
		AvatarStorageDir:          envOrDefault("AVATAR_STORAGE_DIR", "data/avatars"),
		JWTPrivateKeyPath:         os.Getenv("JWT_PRIVATE_KEY_PATH"),
		JWTKeyID:                  os.Getenv("JWT_KEY_ID"),
		JWTKeysetDir:              os.Getenv("JWT_KEYSET_DIR"),
		JWTActiveKeyID:            os.Getenv("JWT_ACTIVE_KEY_ID"),
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
		ConfiguredEnv:    configuredEnvKeys(),
	}
	if err := validateProductionConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validateCaptchaConfig ensures CAPTCHA_PROVIDER, CAPTCHA_SITE_KEY, and
// CAPTCHA_SECRET_KEY are either all empty (disabled) or all set to a recognised
// provider (turnstile/hcaptcha/recaptcha).
//
// Call chain: config.Load → validateCaptchaConfig → (no downstream)
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

// validateProductionConfig rejects dangerous defaults when APP_ENV=production
// (e.g. HTTP issuer URL, missing DSN, missing SMTP host).
//
// Call chain: config.Load → validateProductionConfig → (no downstream)
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
	legacyKeyConfigured := strings.TrimSpace(cfg.JWTPrivateKeyPath) != "" && strings.TrimSpace(cfg.JWTKeyID) != ""
	keysetConfigured := strings.TrimSpace(cfg.JWTKeysetDir) != "" && strings.TrimSpace(cfg.JWTActiveKeyID) != ""
	if !legacyKeyConfigured && !keysetConfigured {
		issues = append(issues, "JWT_PRIVATE_KEY_PATH or JWT_KEYSET_DIR is required in production")
		issues = append(issues, "JWT_KEY_ID or JWT_ACTIVE_KEY_ID is required in production")
	}
	if strings.TrimSpace(cfg.JWTKeysetDir) != "" && strings.TrimSpace(cfg.JWTActiveKeyID) == "" {
		issues = append(issues, "JWT_ACTIVE_KEY_ID is required when JWT_KEYSET_DIR is configured")
	}
	if strings.TrimSpace(cfg.JWTPrivateKeyPath) != "" && strings.TrimSpace(cfg.JWTKeyID) == "" && strings.TrimSpace(cfg.JWTKeysetDir) == "" {
		issues = append(issues, "JWT_KEY_ID is required when JWT_PRIVATE_KEY_PATH is configured")
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

// EnvConfigured reports whether the named environment variable was explicitly set
// to a non-empty value during startup. The second return value is false when the
// key is unknown (not in the EnvDefinitions catalogue).
//
// Call chain: runtime config handlers → Config.EnvConfigured → (no downstream)
func (c Config) EnvConfigured(key string) (bool, bool) {
	if c.ConfiguredEnv == nil {
		return false, false
	}
	configured, ok := c.ConfiguredEnv[key]
	return configured, ok
}

// configuredEnvKeys snapshots every recognised env var as set (true) or absent/empty (false).
//
// Call chain: config.Load → configuredEnvKeys → EnvDefinitions
func configuredEnvKeys() map[string]bool {
	result := make(map[string]bool, len(EnvDefinitions()))
	for _, definition := range EnvDefinitions() {
		value, ok := os.LookupEnv(definition.Name)
		result[definition.Name] = ok && strings.TrimSpace(value) != ""
	}
	return result
}

// envOrDefault returns the trimmed value of the named env var, or fallback when empty.
//
// Call chain: config.Load → envOrDefault → os.Getenv
func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

// defaultCORSAllowCredentials defaults CORS credentials to true unless the origin
// list contains "*". Wildcard origins are incompatible with credentialed requests.
//
// Call chain: config.Load → defaultCORSAllowCredentials → (no downstream)
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

// parseDurationEnv reads key, parses it as a time.Duration, or returns fallback.
//
// Call chain: config.Load → parseDurationEnv → os.Getenv / time.ParseDuration
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

// parseIntEnv reads key, parses it as an int, or returns fallback.
//
// Call chain: config.Load → parseIntEnv → os.Getenv / strconv.Atoi
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

// parseInt64Env reads key, parses it as an int64, or returns fallback.
//
// Call chain: config.Load → parseInt64Env → os.Getenv / strconv.ParseInt
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

// parseBoolEnv reads key, parses it as a bool, or returns fallback.
//
// Call chain: config.Load → parseBoolEnv → os.Getenv / strconv.ParseBool
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

// splitCSV splits a comma-separated string into trimmed, non-empty parts.
// An empty input returns nil.
//
// Call chain: config.Load → splitCSV → (no downstream)
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

// splitUniqueCSV splits a CSV string and deduplicates entries (case-sensitive).
//
// Call chain: config.Load → splitUniqueCSV → splitCSV
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

// splitUniqueLowerCSV splits a CSV string, lowercases every part, and deduplicates.
//
// Call chain: config.Load → splitUniqueLowerCSV → splitCSV
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
