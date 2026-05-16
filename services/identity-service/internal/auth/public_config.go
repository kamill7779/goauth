package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

type PublicConfigHandler struct {
	cfg config.Config
}

func NewPublicConfigHandler(cfg config.Config) *PublicConfigHandler {
	return &PublicConfigHandler{cfg: cfg}
}

func (h *PublicConfigHandler) RegisterRoutes(router gin.IRoutes) {
	router.GET("/public-config", h.get)
}

func (h *PublicConfigHandler) get(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer_url": strings.TrimSpace(h.cfg.PublicIssuerURL),
		"registration": gin.H{
			"mode": defaultString(h.cfg.RegistrationMode, "open"),
		},
		"local_login": gin.H{
			"enabled": h.cfg.LocalPasswordLoginEnabled,
		},
		"captcha": gin.H{
			"provider": publicCaptchaProvider(h.cfg),
			"site_key": publicCaptchaSiteKey(h.cfg),
			"actions":  h.cfg.CaptchaActions,
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
			"provider": defaultString(h.cfg.MailerProvider, "console"),
		},
		"brand": gin.H{
			"name":      defaultString(h.cfg.BrandName, "GoAuth"),
			"tagline":   strings.TrimSpace(h.cfg.BrandTagline),
			"icon_text": defaultString(h.cfg.BrandIconText, "G"),
			"icon_url":  strings.TrimSpace(h.cfg.BrandIconURL),
		},
	})
}

func (h *PublicConfigHandler) externalProviders() []gin.H {
	if !githubPublicProviderEnabled(h.cfg) {
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

func githubPublicProviderEnabled(cfg config.Config) bool {
	return cfg.GitHubOAuthEnabled &&
		strings.TrimSpace(cfg.GitHubClientID) != "" &&
		strings.TrimSpace(cfg.GitHubClientSecret) != "" &&
		strings.TrimSpace(cfg.GitHubRedirectURI) != ""
}

func publicCaptchaProvider(cfg config.Config) string {
	if !publicCaptchaEnabled(cfg) {
		return ""
	}
	return cfg.CaptchaProvider
}

func publicCaptchaSiteKey(cfg config.Config) string {
	if !publicCaptchaEnabled(cfg) {
		return ""
	}
	return cfg.CaptchaSiteKey
}

func publicCaptchaEnabled(cfg config.Config) bool {
	return strings.TrimSpace(cfg.CaptchaProvider) != "" &&
		strings.TrimSpace(cfg.CaptchaSiteKey) != "" &&
		strings.TrimSpace(cfg.CaptchaSecretKey) != ""
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
