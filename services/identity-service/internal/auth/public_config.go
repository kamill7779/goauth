package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/util"
)

type PublicConfigHandler struct {
	cfg config.Config
}

// NewPublicConfigHandler creates a handler that exposes non-sensitive runtime
// configuration to unauthenticated clients (issuer URL, registration mode, etc.).
func NewPublicConfigHandler(cfg config.Config) *PublicConfigHandler {
	return &PublicConfigHandler{cfg: cfg}
}

// RegisterRoutes mounts the public-config endpoint.
func (h *PublicConfigHandler) RegisterRoutes(router gin.IRoutes) {
	router.GET("/public-config", h.get)
}

// get returns the public configuration as JSON.
//
// Call chain: GET /public-config → get → config values
func (h *PublicConfigHandler) get(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer_url": strings.TrimSpace(h.cfg.PublicIssuerURL),
		"registration": gin.H{
			"mode": util.DefaultString(h.cfg.RegistrationMode, "open"),
		},
		"local_login": gin.H{
			"enabled": h.cfg.LocalPasswordLoginEnabled,
		},
		"captcha": gin.H{
			"provider": publicCaptchaProvider(h.cfg),
			"site_key": publicCaptchaSiteKey(h.cfg),
			"actions":  h.cfg.CaptchaActions,
		},
		"human_check": gin.H{
			"provider": publicHumanCheckProvider(h.cfg),
			"actions":  publicHumanCheckActions(h.cfg),
		},
		"external_providers": h.externalProviders(),
		"password_policy": gin.H{
			"min_length":        h.cfg.PasswordMinLength,
			"require_uppercase": h.cfg.PasswordRequireUpper,
			"require_lowercase": h.cfg.PasswordRequireLower,
			"require_digit":     h.cfg.PasswordRequireDigit,
			"require_special":   h.cfg.PasswordRequireSpecial,
			"history_count":     h.cfg.PasswordHistoryCount,
		},
		"mailer": gin.H{
			"provider": util.DefaultString(h.cfg.MailerProvider, "console"),
		},
		"brand": gin.H{
			"name":      util.DefaultString(h.cfg.BrandName, "GoAuth"),
			"tagline":   strings.TrimSpace(h.cfg.BrandTagline),
			"icon_text": util.DefaultString(h.cfg.BrandIconText, "G"),
			"icon_url":  strings.TrimSpace(h.cfg.BrandIconURL),
		},
	})
}

// externalProviders returns the list of configured external IdP providers.
func (h *PublicConfigHandler) externalProviders() []gin.H {
	if !h.cfg.IsGitHubConfigured() {
		return []gin.H{}
	}
	return []gin.H{
		{
			"slug":         "github",
			"display_name": "GitHub",
			"start_url":    "/v1/external/github/start",
		},
	}
}

// publicCaptchaProvider returns the CAPTCHA provider name when CAPTCHA is enabled.
func publicCaptchaProvider(cfg config.Config) string {
	if !publicCaptchaEnabled(cfg) {
		return ""
	}
	return cfg.CaptchaProvider
}

// publicCaptchaSiteKey returns the CAPTCHA site key when CAPTCHA is enabled.
func publicCaptchaSiteKey(cfg config.Config) string {
	if !publicCaptchaEnabled(cfg) {
		return ""
	}
	return cfg.CaptchaSiteKey
}

// publicCaptchaEnabled reports whether CAPTCHA is fully configured.
func publicCaptchaEnabled(cfg config.Config) bool {
	return strings.TrimSpace(cfg.CaptchaProvider) != "" &&
		strings.TrimSpace(cfg.CaptchaSiteKey) != "" &&
		strings.TrimSpace(cfg.CaptchaSecretKey) != ""
}

// publicHumanCheckProvider returns the browser-safe human check provider name.
func publicHumanCheckProvider(cfg config.Config) string {
	if !publicHumanCheckEnabled(cfg) {
		return ""
	}
	return cfg.HumanCheckProvider
}

// publicHumanCheckActions returns the human-check action allowlist when enabled.
func publicHumanCheckActions(cfg config.Config) []string {
	if !publicHumanCheckEnabled(cfg) {
		return []string{}
	}
	return cfg.HumanCheckActions
}

// publicHumanCheckEnabled reports whether self-hosted human check is configured.
func publicHumanCheckEnabled(cfg config.Config) bool {
	return strings.TrimSpace(cfg.HumanCheckProvider) != "" && len(cfg.HumanCheckActions) > 0
}
