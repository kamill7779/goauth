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
}

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

	corsAllowCredentials, err := parseBoolEnv("CORS_ALLOW_CREDENTIALS", false)
	if err != nil {
		return Config{}, err
	}

	githubOAuthEnabled, err := parseBoolEnv("GITHUB_OAUTH_ENABLED", false)
	if err != nil {
		return Config{}, err
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

	return Config{
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
		CORSAllowedOrigins:        splitCSV(envOrDefault("CORS_ALLOWED_ORIGINS", "")),
		CORSAllowedMethods:        splitCSV(envOrDefault("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE")),
		CORSAllowedHeaders:        splitCSV(envOrDefault("CORS_ALLOWED_HEADERS", "Authorization,Content-Type")),
		CORSAllowCredentials:      corsAllowCredentials,
		GitHubOAuthEnabled:        githubOAuthEnabled,
		GitHubClientID:            os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:        os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURI:         os.Getenv("GITHUB_REDIRECT_URI"),
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

		CaptchaProvider:  strings.ToLower(strings.TrimSpace(os.Getenv("CAPTCHA_PROVIDER"))),
		CaptchaSecretKey: os.Getenv("CAPTCHA_SECRET_KEY"),
		CaptchaSiteKey:   os.Getenv("CAPTCHA_SITE_KEY"),
	}, nil
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
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
