package admin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
	httpserver "goauth/services/identity-service/internal/http"
)

type runtimeConfigItem struct {
	Key          string `json:"key"`
	Group        string `json:"group"`
	Status       string `json:"status"`
	Configured   bool   `json:"configured"`
	Required     bool   `json:"required"`
	Secret       bool   `json:"secret"`
	PublicConfig bool   `json:"public_config"`
	Source       string `json:"source"`
	Message      string `json:"message"`
}

func (h *Handler) runtimeConfig(c *gin.Context) {
	cfg := h.cfg
	production := strings.EqualFold(strings.TrimSpace(cfg.AppEnv), "production")
	groups := map[string][]runtimeConfigItem{}
	order := []string{}

	for _, definition := range config.EnvDefinitions() {
		item := h.runtimeConfigItem(definition, production)
		if _, exists := groups[item.Group]; !exists {
			order = append(order, item.Group)
		}
		groups[item.Group] = append(groups[item.Group], item)
	}

	responseGroups := make([]gin.H, 0, len(order))
	for _, group := range order {
		responseGroups = append(responseGroups, gin.H{
			"key":   group,
			"items": groups[group],
		})
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"environment": defaultRuntimeString(cfg.AppEnv, "development"),
		"groups":      responseGroups,
	})
}

func (h *Handler) runtimeConfigItem(definition config.EnvDefinition, production bool) runtimeConfigItem {
	cfg := h.cfg
	configured := h.configuredFromRuntimeSource(definition.Name)
	required := definition.RequiredInProduction && production
	status := "ok"
	message := "configured"
	source := "configured"

	if !configured {
		source = "default"
		if definition.Default == "" {
			source = "empty"
			message = "not configured"
		} else {
			message = "using default"
		}
	}

	if required && !configured {
		status = "error"
		message = "required in production"
	}

	switch definition.Name {
	case "PUBLIC_ISSUER_URL":
		if production && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.PublicIssuerURL)), "https://") {
			status = "error"
			message = "production issuer must use HTTPS"
			required = true
		}
	case "REGISTRATION_MODE":
		if production && strings.EqualFold(strings.TrimSpace(cfg.RegistrationMode), "open") {
			status = "warning"
			message = "open registration is enabled in production"
		}
	case "JWT_PRIVATE_KEY_PATH":
		if production && strings.TrimSpace(cfg.JWTKeysetDir) == "" {
			required = true
			if strings.TrimSpace(cfg.JWTPrivateKeyPath) == "" {
				status = "error"
				message = "persistent signing key is required in production"
			}
		}
	case "JWT_KEY_ID":
		if production && strings.TrimSpace(cfg.JWTKeysetDir) == "" {
			required = true
			if strings.TrimSpace(cfg.JWTKeyID) == "" {
				status = "error"
				message = "required with JWT_PRIVATE_KEY_PATH"
			}
		}
	case "JWT_KEYSET_DIR":
		if production && strings.TrimSpace(cfg.JWTPrivateKeyPath) == "" {
			required = true
			if strings.TrimSpace(cfg.JWTKeysetDir) == "" {
				status = "error"
				message = "persistent signing keyset is required in production"
			}
		}
	case "JWT_ACTIVE_KEY_ID":
		if strings.TrimSpace(cfg.JWTKeysetDir) != "" {
			required = true
			if !configured {
				status = "error"
				message = "required with JWT_KEYSET_DIR"
			}
		}
	case "MAILER_PROVIDER":
		if production && strings.EqualFold(strings.TrimSpace(cfg.MailerProvider), "noop") {
			status = "warning"
			message = "noop mailer drops email in production"
		}
	case "SMTP_HOST", "SMTP_FROM":
		if strings.EqualFold(strings.TrimSpace(cfg.MailerProvider), "smtp") {
			required = true
			if !configured {
				status = "error"
				message = "required when MAILER_PROVIDER=smtp"
			}
		}
	case "CAPTCHA_PROVIDER", "CAPTCHA_SITE_KEY", "CAPTCHA_SECRET_KEY":
		if captchaPartiallyConfigured(cfg) {
			required = true
			if !configured {
				status = "error"
				message = "CAPTCHA provider, site key, and secret key must be set together"
			}
		}
	case "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "GITHUB_REDIRECT_URI":
		if cfg.GitHubOAuthEnabled {
			required = true
			if !configured {
				status = "error"
				message = "required when GITHUB_OAUTH_ENABLED=true"
			}
		}
	case "BOOTSTRAP_ADMIN_PASSWORD":
		if production && configured {
			status = "warning"
			message = "remove bootstrap password after first admin is created"
		}
	}

	return runtimeConfigItem{
		Key:          definition.Name,
		Group:        definition.Group,
		Status:       status,
		Configured:   configured,
		Required:     required,
		Secret:       definition.Secret,
		PublicConfig: definition.PublicConfig,
		Source:       source,
		Message:      message,
	}
}

func (h *Handler) configuredFromRuntimeSource(key string) bool {
	if configured, ok := h.cfg.EnvConfigured(key); ok {
		return configured
	}
	return h.configured(key)
}

func (h *Handler) configured(key string) bool {
	cfg := h.cfg
	switch key {
	case "APP_ENV":
		return strings.TrimSpace(cfg.AppEnv) != ""
	case "HTTP_ADDR":
		return strings.TrimSpace(cfg.HTTPAddr) != ""
	case "PUBLIC_ISSUER_URL":
		return strings.TrimSpace(cfg.PublicIssuerURL) != ""
	case "BROWSER_LOGIN_URL":
		return strings.TrimSpace(cfg.BrowserLoginURL) != ""
	case "BROWSER_COOKIE_SECURE":
		return cfg.BrowserCookieSecure
	case "MYSQL_DSN":
		return strings.TrimSpace(cfg.MySQLDSN) != ""
	case "REDIS_URL":
		return strings.TrimSpace(cfg.RedisURL) != ""
	case "JWT_PRIVATE_KEY_PATH":
		return strings.TrimSpace(cfg.JWTPrivateKeyPath) != ""
	case "JWT_KEY_ID":
		return strings.TrimSpace(cfg.JWTKeyID) != ""
	case "JWT_KEYSET_DIR":
		return strings.TrimSpace(cfg.JWTKeysetDir) != ""
	case "JWT_ACTIVE_KEY_ID":
		return strings.TrimSpace(cfg.JWTActiveKeyID) != ""
	case "ACCESS_TOKEN_TTL":
		return cfg.AccessTokenTTL > 0
	case "BROWSER_SESSION_TTL":
		return cfg.BrowserSessionTTL > 0
	case "REFRESH_TOKEN_TTL":
		return cfg.RefreshTokenTTL > 0
	case "TRUSTED_PROXIES":
		return len(cfg.TrustedProxies) > 0
	case "SMTP_HOST":
		return strings.TrimSpace(cfg.SMTPHost) != ""
	case "SMTP_PORT":
		return cfg.SMTPPort > 0
	case "SMTP_USERNAME":
		return strings.TrimSpace(cfg.SMTPUsername) != ""
	case "SMTP_PASSWORD":
		return strings.TrimSpace(cfg.SMTPPassword) != ""
	case "SMTP_FROM":
		return strings.TrimSpace(cfg.SMTPFrom) != ""
	case "SMTP_SSL":
		return cfg.SMTPSSLEnabled
	case "SMTP_AUTH_LOGIN":
		return cfg.SMTPAuthLogin
	case "CORS_ALLOWED_ORIGINS":
		return len(cfg.CORSAllowedOrigins) > 0
	case "CORS_ALLOWED_METHODS":
		return len(cfg.CORSAllowedMethods) > 0
	case "CORS_ALLOWED_HEADERS":
		return len(cfg.CORSAllowedHeaders) > 0
	case "CORS_ALLOW_CREDENTIALS":
		return cfg.CORSAllowCredentials
	case "REGISTRATION_MODE":
		return strings.TrimSpace(cfg.RegistrationMode) != ""
	case "LOCAL_PASSWORD_LOGIN_ENABLED":
		return cfg.LocalPasswordLoginEnabled
	case "MAILER_PROVIDER":
		return strings.TrimSpace(cfg.MailerProvider) != ""
	case "BRAND_NAME":
		return strings.TrimSpace(cfg.BrandName) != ""
	case "BRAND_TAGLINE":
		return strings.TrimSpace(cfg.BrandTagline) != ""
	case "BRAND_ICON_TEXT":
		return strings.TrimSpace(cfg.BrandIconText) != ""
	case "BRAND_ICON_URL":
		return strings.TrimSpace(cfg.BrandIconURL) != ""
	case "GITHUB_OAUTH_ENABLED":
		return cfg.GitHubOAuthEnabled
	case "GITHUB_CLIENT_ID":
		return strings.TrimSpace(cfg.GitHubClientID) != ""
	case "GITHUB_CLIENT_SECRET":
		return strings.TrimSpace(cfg.GitHubClientSecret) != ""
	case "GITHUB_REDIRECT_URI":
		return strings.TrimSpace(cfg.GitHubRedirectURI) != ""
	case "DEFAULT_MEMBER_TENANT_SLUGS":
		return len(cfg.DefaultMemberTenantSlugs) > 0
	case "BOOTSTRAP_ADMIN_EMAIL":
		return strings.TrimSpace(cfg.BootstrapAdminEmail) != ""
	case "BOOTSTRAP_ADMIN_PASSWORD":
		return strings.TrimSpace(cfg.BootstrapAdminPassword) != ""
	case "BOOTSTRAP_ADMIN_USERNAME":
		return strings.TrimSpace(cfg.BootstrapAdminUsername) != ""
	case "BOOTSTRAP_ADMIN_NICKNAME":
		return strings.TrimSpace(cfg.BootstrapAdminNickname) != ""
	case "BOOTSTRAP_ADMIN_DISPLAY_NAME":
		return strings.TrimSpace(cfg.BootstrapAdminDisplayName) != ""
	case "BOOTSTRAP_ADMIN_ROLE":
		return strings.TrimSpace(cfg.BootstrapAdminRoleCode) != ""
	case "LOCKOUT_THRESHOLD":
		return cfg.LockoutThreshold > 0
	case "LOCKOUT_DURATION":
		return cfg.LockoutDuration > 0
	case "METRICS_ENABLED":
		return cfg.MetricsEnabled
	case "PASSWORD_MIN_LENGTH":
		return cfg.PasswordMinLength > 0
	case "PASSWORD_REQUIRE_UPPERCASE":
		return cfg.PasswordRequireUpper
	case "PASSWORD_REQUIRE_LOWERCASE":
		return cfg.PasswordRequireLower
	case "PASSWORD_REQUIRE_DIGIT":
		return cfg.PasswordRequireDigit
	case "PASSWORD_REQUIRE_SPECIAL":
		return cfg.PasswordRequireSpecial
	case "PASSWORD_HISTORY_COUNT":
		return cfg.PasswordHistoryCount > 0
	case "DEFAULT_LOCALE":
		return strings.TrimSpace(cfg.DefaultLocale) != ""
	case "CAPTCHA_PROVIDER":
		return strings.TrimSpace(cfg.CaptchaProvider) != ""
	case "CAPTCHA_SECRET_KEY":
		return strings.TrimSpace(cfg.CaptchaSecretKey) != ""
	case "CAPTCHA_SITE_KEY":
		return strings.TrimSpace(cfg.CaptchaSiteKey) != ""
	case "CAPTCHA_ACTIONS":
		return len(cfg.CaptchaActions) > 0
	default:
		return false
	}
}

func captchaPartiallyConfigured(cfg config.Config) bool {
	return strings.TrimSpace(cfg.CaptchaProvider) != "" ||
		strings.TrimSpace(cfg.CaptchaSiteKey) != "" ||
		strings.TrimSpace(cfg.CaptchaSecretKey) != ""
}

func defaultRuntimeString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
