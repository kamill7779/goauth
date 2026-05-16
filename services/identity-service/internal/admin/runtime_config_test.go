package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

func TestRuntimeConfigSummarizesConfigurationWithoutSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(nil, nil, nil, nil, nil, config.Config{
		AppEnv:                    "production",
		PublicIssuerURL:           "https://auth.example.com",
		MySQLDSN:                  "root:secret@tcp(mysql:3306)/goauth",
		RedisURL:                  "redis://:secret@redis:6379/0",
		JWTPrivateKeyPath:         "/run/secrets/jwt.pem",
		JWTKeyID:                  "prod-key",
		MailerProvider:            "smtp",
		SMTPHost:                  "smtp.example.com",
		SMTPPassword:              "smtp-secret",
		SMTPFrom:                  "noreply@example.com",
		RegistrationMode:          "open",
		LocalPasswordLoginEnabled: true,
		CaptchaProvider:           "turnstile",
		CaptchaSiteKey:            "site-key",
		CaptchaSecretKey:          "captcha-secret",
		CaptchaActions:            []string{"login", "register"},
		GitHubOAuthEnabled:        true,
		GitHubClientID:            "github-client",
		GitHubClientSecret:        "github-secret",
		GitHubRedirectURI:         "https://auth.example.com/v1/external/github/callback",
		BootstrapAdminEmail:       "root@example.com",
		BootstrapAdminPassword:    "bootstrap-secret",
		BrandName:                 "Acme ID",
	})

	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/runtime-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	for _, forbidden := range []string{
		"smtp-secret",
		"captcha-secret",
		"github-secret",
		"bootstrap-secret",
		"root:secret",
		"redis://:secret",
		"/run/secrets/jwt.pem",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("runtime config leaked %q: %s", forbidden, body)
		}
	}

	var envelope struct {
		Data struct {
			Environment string `json:"environment"`
			Groups      []struct {
				Key   string `json:"key"`
				Items []struct {
					Key      string `json:"key"`
					Status   string `json:"status"`
					Source   string `json:"source"`
					Required bool   `json:"required"`
				} `json:"items"`
			} `json:"groups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data.Environment != "production" {
		t.Fatalf("environment = %q, want production", envelope.Data.Environment)
	}

	items := map[string]struct {
		Status   string
		Required bool
	}{}
	for _, group := range envelope.Data.Groups {
		for _, item := range group.Items {
			items[item.Key] = struct {
				Status   string
				Required bool
			}{Status: item.Status, Required: item.Required}
		}
	}

	for _, key := range []string{"MYSQL_DSN", "REDIS_URL", "JWT_PRIVATE_KEY_PATH", "JWT_KEY_ID", "MAILER_PROVIDER", "CAPTCHA_SECRET_KEY", "GITHUB_CLIENT_SECRET"} {
		item, ok := items[key]
		if !ok {
			t.Fatalf("runtime config omitted %s", key)
		}
		if item.Status != "ok" {
			t.Fatalf("%s status = %q, want ok", key, item.Status)
		}
	}
	if !items["JWT_PRIVATE_KEY_PATH"].Required {
		t.Fatal("JWT_PRIVATE_KEY_PATH should be required in production")
	}
}

func TestRuntimeConfigFlagsProductionRisks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(nil, nil, nil, nil, nil, config.Config{
		AppEnv:           "production",
		PublicIssuerURL:  "http://auth.example.com",
		RegistrationMode: "open",
		MailerProvider:   "smtp",
		CaptchaProvider:  "turnstile",
		CaptchaSiteKey:   "site-key",
	})

	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/runtime-config", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	for _, expected := range []string{
		`"key":"PUBLIC_ISSUER_URL"`,
		`"key":"REGISTRATION_MODE"`,
		`"open registration is enabled in production"`,
		`"key":"JWT_PRIVATE_KEY_PATH"`,
		`"key":"SMTP_HOST"`,
		`"key":"CAPTCHA_SECRET_KEY"`,
		`"status":"error"`,
		`"status":"warning"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("runtime config missing %s: %s", expected, body)
		}
	}
}

func TestRuntimeConfigUsesExplicitEnvSourceMetadata(t *testing.T) {
	handler := NewHandler(nil, nil, nil, nil, nil, config.Config{
		PublicIssuerURL:           "http://127.0.0.1:8080",
		RegistrationMode:          "open",
		LocalPasswordLoginEnabled: false,
		MailerProvider:            "console",
		ConfiguredEnv: map[string]bool{
			"PUBLIC_ISSUER_URL":            false,
			"REGISTRATION_MODE":           false,
			"LOCAL_PASSWORD_LOGIN_ENABLED": true,
			"MAILER_PROVIDER":             false,
		},
	})

	publicIssuer := handler.runtimeConfigItem(envDefinition(t, "PUBLIC_ISSUER_URL"), false)
	if publicIssuer.Configured {
		t.Fatal("PUBLIC_ISSUER_URL should be reported as default-sourced when env was not set")
	}
	if publicIssuer.Source != "default" {
		t.Fatalf("PUBLIC_ISSUER_URL source = %q, want default", publicIssuer.Source)
	}

	localLogin := handler.runtimeConfigItem(envDefinition(t, "LOCAL_PASSWORD_LOGIN_ENABLED"), false)
	if !localLogin.Configured {
		t.Fatal("LOCAL_PASSWORD_LOGIN_ENABLED=false should still be reported as explicitly configured")
	}
	if localLogin.Source != "configured" {
		t.Fatalf("LOCAL_PASSWORD_LOGIN_ENABLED source = %q, want configured", localLogin.Source)
	}
}

func envDefinition(t *testing.T, key string) config.EnvDefinition {
	t.Helper()
	for _, definition := range config.EnvDefinitions() {
		if definition.Name == key {
			return definition
		}
	}
	t.Fatalf("missing env definition for %s", key)
	return config.EnvDefinition{}
}
