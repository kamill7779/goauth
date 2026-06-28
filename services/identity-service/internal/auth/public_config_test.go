package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

func TestPublicConfigDoesNotExposeSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewPublicConfigHandler(config.Config{
		RegistrationMode:          "open",
		LocalPasswordLoginEnabled: true,
		MailerProvider:            "console",
		CaptchaProvider:           "turnstile",
		CaptchaSiteKey:            "site-key",
		CaptchaSecretKey:          "secret-key",
		CaptchaActions:            []string{"login", "register"},
		HumanCheckProvider:        "slider",
		HumanCheckActions:         []string{"register"},
		PublicIssuerURL:           "https://auth.example.com",
		GitHubOAuthEnabled:        true,
		GitHubClientID:            "client-id",
		GitHubClientSecret:        "client-secret",
		GitHubRedirectURI:         "https://auth.example.com/v1/external/github/callback",
		PasswordMinLength:         8,
		PasswordRequireDigit:      true,
		BrandName:                 "Acme Login",
		BrandTagline:              "Identity for Acme",
		BrandIconText:             "A",
		BrandIconURL:              "https://cdn.example.com/acme.svg",
	})

	router := gin.New()
	h.RegisterRoutes(router.Group("/v1/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/public-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret-key") || strings.Contains(body, "client-secret") {
		t.Fatalf("public config leaked secret: %s", body)
	}
	if !strings.Contains(body, "site-key") || !strings.Contains(body, "GitHub") {
		t.Fatalf("public config omitted public capabilities: %s", body)
	}
	if !strings.Contains(body, "Acme Login") || !strings.Contains(body, "Identity for Acme") || !strings.Contains(body, "https://cdn.example.com/acme.svg") {
		t.Fatalf("public config omitted branding: %s", body)
	}
	if !strings.Contains(body, "https://auth.example.com") {
		t.Fatalf("public config omitted public issuer URL: %s", body)
	}
	if !strings.Contains(body, "human_check") || !strings.Contains(body, "slider") {
		t.Fatalf("public config omitted human check capability: %s", body)
	}
}

func TestPublicConfigHumanCheckEnabledOnlyWithProviderAndActions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewPublicConfigHandler(config.Config{
		HumanCheckProvider: "slider",
		HumanCheckActions:  []string{"register"},
	})

	router := gin.New()
	h.RegisterRoutes(router.Group("/v1/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/public-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response struct {
		HumanCheck struct {
			Provider string   `json:"provider"`
			Actions  []string `json:"actions"`
		} `json:"human_check"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.HumanCheck.Provider != "slider" {
		t.Fatalf("human_check.provider = %q, want slider", response.HumanCheck.Provider)
	}
	if len(response.HumanCheck.Actions) != 1 || response.HumanCheck.Actions[0] != "register" {
		t.Fatalf("human_check.actions = %v, want [register]", response.HumanCheck.Actions)
	}
}

func TestPublicConfigOmitsDisabledGitHubProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewPublicConfigHandler(config.Config{
		RegistrationMode:          "disabled",
		LocalPasswordLoginEnabled: true,
		GitHubOAuthEnabled:        true,
		GitHubClientSecret:        "client-secret",
	})

	router := gin.New()
	h.RegisterRoutes(router.Group("/v1/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/public-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response struct {
		Registration struct {
			Mode string `json:"mode"`
		} `json:"registration"`
		ExternalProviders []struct {
			Slug string `json:"slug"`
		} `json:"external_providers"`
		Mailer struct {
			Provider string `json:"provider"`
		} `json:"mailer"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Registration.Mode != "disabled" {
		t.Fatalf("registration mode = %q, want disabled", response.Registration.Mode)
	}
	if len(response.ExternalProviders) != 0 {
		t.Fatalf("external providers = %v, want empty", response.ExternalProviders)
	}
}

func TestPublicConfigOmitsIncompleteGitHubProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewPublicConfigHandler(config.Config{
		GitHubOAuthEnabled: true,
		GitHubClientID:     "client-id",
		GitHubRedirectURI:  "https://auth.example.com/v1/external/github/callback",
	})

	router := gin.New()
	h.RegisterRoutes(router.Group("/v1/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/public-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(rec.Body.String(), "GitHub") {
		t.Fatalf("public config exposed incomplete GitHub provider: %s", rec.Body.String())
	}
}

func TestPublicConfigDisablesIncompleteCaptcha(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewPublicConfigHandler(config.Config{
		CaptchaProvider: "turnstile",
		CaptchaSiteKey:  "site-key",
		CaptchaActions:  []string{"login"},
	})

	router := gin.New()
	h.RegisterRoutes(router.Group("/v1/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/public-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var response struct {
		Captcha struct {
			Provider string `json:"provider"`
			SiteKey  string `json:"site_key"`
		} `json:"captcha"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Captcha.Provider != "" || response.Captcha.SiteKey != "" {
		t.Fatalf("captcha = %+v, want disabled for incomplete config", response.Captcha)
	}
}
