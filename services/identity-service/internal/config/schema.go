package config

type EnvDefinition struct {
	Name                 string `json:"name"`
	Group                string `json:"group"`
	Default              string `json:"default"`
	RequiredInProduction bool   `json:"required_in_production"`
	Secret               bool   `json:"secret"`
	PublicConfig         bool   `json:"public_config"`
	Description          string `json:"description"`
}

func EnvDefinitions() []EnvDefinition {
	return []EnvDefinition{
		env("APP_ENV", "core", "development", false, false, false, "Runtime environment name."),
		env("HTTP_ADDR", "core", ":8080", false, false, false, "HTTP listen address."),
		env("PUBLIC_ISSUER_URL", "core", "http://127.0.0.1:8080", true, false, true, "Externally reachable OIDC issuer URL."),
		env("BROWSER_LOGIN_URL", "core", "/login", false, false, false, "Browser login URL used by OIDC redirects."),
		env("BROWSER_COOKIE_SECURE", "core", "derived", false, false, false, "Whether browser SSO cookies require HTTPS."),
		env("MYSQL_DSN", "storage", "", true, true, false, "MySQL connection string."),
		env("REDIS_URL", "storage", "", true, true, false, "Redis connection URL."),
		env("AVATAR_STORAGE_DIR", "storage", "data/avatars", false, false, false, "Local directory for account avatar uploads."),
		env("JWT_PRIVATE_KEY_PATH", "tokens", "", false, true, false, "Path to persistent RSA private key."),
		env("JWT_KEY_ID", "tokens", "", false, false, false, "Legacy single-key JWKS key id."),
		env("JWT_KEYSET_DIR", "tokens", "", false, true, false, "Directory of RSA private keys named by kid, for key rotation."),
		env("JWT_ACTIVE_KEY_ID", "tokens", "", false, false, false, "Active JWT signing key id from JWT_KEYSET_DIR."),
		env("ACCESS_TOKEN_TTL", "tokens", "15m", false, false, false, "Access token lifetime."),
		env("BROWSER_SESSION_TTL", "tokens", "12h", false, false, false, "Browser SSO session lifetime."),
		env("REFRESH_TOKEN_TTL", "tokens", "720h", false, false, false, "Refresh token lifetime."),
		env("TRUSTED_PROXIES", "network", "", false, false, false, "Trusted reverse proxy CIDRs or IPs."),
		env("SMTP_HOST", "mailer", "", false, false, false, "SMTP server host."),
		env("SMTP_PORT", "mailer", "587", false, false, false, "SMTP server port."),
		env("SMTP_USERNAME", "mailer", "", false, false, false, "SMTP username."),
		env("SMTP_PASSWORD", "mailer", "", false, true, false, "SMTP password."),
		env("SMTP_FROM", "mailer", "", false, false, false, "SMTP sender address."),
		env("SMTP_SSL", "mailer", "false", false, false, false, "Use SMTPS direct TLS."),
		env("SMTP_AUTH_LOGIN", "mailer", "false", false, false, false, "Use SMTP AUTH LOGIN instead of AUTH PLAIN."),
		env("CORS_ALLOWED_ORIGINS", "network", "", false, false, false, "Allowed browser origins."),
		env("CORS_ALLOWED_METHODS", "network", "GET,POST,PUT,PATCH,DELETE", false, false, false, "Allowed CORS methods."),
		env("CORS_ALLOWED_HEADERS", "network", "Authorization,Content-Type,X-Captcha-Token,X-Human-Token", false, false, false, "Allowed CORS headers."),
		env("CORS_ALLOW_CREDENTIALS", "network", "derived", false, false, false, "Allow browser credentials in CORS."),
		env("REGISTRATION_MODE", "auth_entry", "open", false, false, true, "Self-service registration mode."),
		env("LOCAL_PASSWORD_LOGIN_ENABLED", "auth_entry", "true", false, false, true, "Enable local password login."),
		env("MAILER_PROVIDER", "mailer", "console", false, false, true, "Mailer provider."),
		env("BRAND_NAME", "branding", "GoAuth", false, false, true, "Public brand name."),
		env("BRAND_TAGLINE", "branding", "", false, false, true, "Public brand tagline."),
		env("BRAND_ICON_TEXT", "branding", "G", false, false, true, "Public fallback brand icon text."),
		env("BRAND_ICON_URL", "branding", "", false, false, true, "Public brand icon URL."),
		env("GITHUB_OAUTH_ENABLED", "external_login", "false", false, false, true, "Enable GitHub external login."),
		env("GITHUB_CLIENT_ID", "external_login", "", false, false, false, "GitHub OAuth client id."),
		env("GITHUB_CLIENT_SECRET", "external_login", "", false, true, false, "GitHub OAuth client secret."),
		env("GITHUB_REDIRECT_URI", "external_login", "derived", false, false, false, "GitHub OAuth callback URI."),
		env("DEFAULT_MEMBER_TENANT_SLUGS", "tenancy", "", false, false, false, "Default tenant slugs for newly created members."),
		env("BOOTSTRAP_ADMIN_EMAIL", "bootstrap", "", false, false, false, "Bootstrap admin email."),
		env("BOOTSTRAP_ADMIN_PASSWORD", "bootstrap", "", false, true, false, "Bootstrap admin password."),
		env("BOOTSTRAP_ADMIN_USERNAME", "bootstrap", "", false, false, false, "Bootstrap admin username."),
		env("BOOTSTRAP_ADMIN_NICKNAME", "bootstrap", "", false, false, false, "Bootstrap admin nickname."),
		env("BOOTSTRAP_ADMIN_DISPLAY_NAME", "bootstrap", "", false, false, false, "Bootstrap admin display name compatibility alias."),
		env("BOOTSTRAP_ADMIN_ROLE", "bootstrap", "root", false, false, false, "Bootstrap admin role code."),
		env("LOCKOUT_THRESHOLD", "security", "5", false, false, false, "Failed login attempts before account lockout."),
		env("LOCKOUT_DURATION", "security", "15m", false, false, false, "Account lockout duration."),
		env("METRICS_ENABLED", "observability", "true", false, false, false, "Enable Prometheus metrics endpoint."),
		env("PASSWORD_MIN_LENGTH", "security", "8", false, false, true, "Minimum password length."),
		env("PASSWORD_REQUIRE_UPPERCASE", "security", "false", false, false, true, "Require uppercase password characters."),
		env("PASSWORD_REQUIRE_LOWERCASE", "security", "false", false, false, true, "Require lowercase password characters."),
		env("PASSWORD_REQUIRE_DIGIT", "security", "true", false, false, true, "Require password digits."),
		env("PASSWORD_REQUIRE_SPECIAL", "security", "false", false, false, true, "Require special password characters."),
		env("PASSWORD_HISTORY_COUNT", "security", "3", false, false, true, "Password history count."),
		env("DEFAULT_LOCALE", "i18n", "en", false, false, false, "Default email locale."),
		env("CAPTCHA_PROVIDER", "captcha", "", false, false, true, "CAPTCHA provider."),
		env("CAPTCHA_SECRET_KEY", "captcha", "", false, true, false, "CAPTCHA server-side secret key."),
		env("CAPTCHA_SITE_KEY", "captcha", "", false, false, true, "CAPTCHA public site key."),
		env("CAPTCHA_ACTIONS", "captcha", "login,register,email_code,password_forgot", false, false, true, "CAPTCHA-protected actions."),
		env("HUMAN_CHECK_PROVIDER", "human_check", "", false, false, true, "Self-hosted human check provider."),
		env("HUMAN_CHECK_ACTIONS", "human_check", "register", false, false, true, "Human-check protected actions."),
		env("HUMAN_CHECK_CHALLENGE_TTL", "human_check", "2m", false, false, false, "Human check challenge lifetime."),
		env("HUMAN_CHECK_TOKEN_TTL", "human_check", "3m", false, false, false, "Human check one-time token lifetime."),
		env("HUMAN_CHECK_SLIDER_TOLERANCE_PX", "human_check", "4", false, false, false, "Accepted slider answer tolerance in pixels."),
	}
}

func env(name, group, fallback string, requiredInProduction, secret, publicConfig bool, description string) EnvDefinition {
	return EnvDefinition{
		Name:                 name,
		Group:                group,
		Default:              fallback,
		RequiredInProduction: requiredInProduction,
		Secret:               secret,
		PublicConfig:         publicConfig,
		Description:          description,
	}
}
