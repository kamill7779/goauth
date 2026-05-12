package mailer_test

import (
	"strings"
	"testing"

	"goauth/services/identity-service/internal/mailer"
)

func TestTemplateEngine_RenderEnglish(t *testing.T) {
	e := mailer.NewTemplateEngine("en")
	subject, body, err := e.Render("email_verification", "en", mailer.TemplateData{
		AppName:   "GoAuth",
		UserName:  "Alice",
		Code:      "123456",
		ExpiryMin: 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(subject, "GoAuth") {
		t.Errorf("subject missing app name: %q", subject)
	}
	if !strings.Contains(body, "123456") {
		t.Errorf("body missing code: %q", body)
	}
	if !strings.Contains(body, "Alice") {
		t.Errorf("body missing user name: %q", body)
	}
}

func TestTemplateEngine_RenderChineseSimplified(t *testing.T) {
	e := mailer.NewTemplateEngine("en")
	subject, body, err := e.Render("email_verification", "zh-CN", mailer.TemplateData{
		AppName:   "GoAuth",
		UserName:  "张三",
		Code:      "654321",
		ExpiryMin: 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(subject, "验证码") {
		t.Errorf("subject should contain Chinese text: %q", subject)
	}
	if !strings.Contains(body, "654321") {
		t.Errorf("body missing code: %q", body)
	}
}

func TestTemplateEngine_FallbackToDefaultLocale(t *testing.T) {
	e := mailer.NewTemplateEngine("en")
	// "fr" locale doesn't exist, should fall back to "en"
	subject, _, err := e.Render("email_verification", "fr", mailer.TemplateData{
		AppName:   "GoAuth",
		UserName:  "Bob",
		Code:      "000000",
		ExpiryMin: 10,
	})
	if err != nil {
		t.Fatalf("unexpected error on fallback: %v", err)
	}
	if subject == "" {
		t.Error("expected non-empty subject on fallback")
	}
}

func TestTemplateEngine_UnknownTemplate(t *testing.T) {
	e := mailer.NewTemplateEngine("en")
	_, _, err := e.Render("nonexistent_type", "en", mailer.TemplateData{})
	if err == nil {
		t.Error("expected error for unknown template type")
	}
}

func TestTemplateEngine_PasswordReset(t *testing.T) {
	e := mailer.NewTemplateEngine("en")
	_, body, err := e.Render("password_reset", "en", mailer.TemplateData{
		AppName:   "GoAuth",
		UserName:  "Carol",
		Code:      "RESET99",
		ExpiryMin: 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(body, "RESET99") {
		t.Errorf("body missing reset code: %q", body)
	}
}

func TestTemplateEngine_TenantInvite(t *testing.T) {
	e := mailer.NewTemplateEngine("en")
	_, body, err := e.Render("tenant_invite", "en", mailer.TemplateData{
		AppName:   "GoAuth",
		UserName:  "Dave",
		Link:      "https://example.com/invite?token=abc",
		ExpiryMin: 4320,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(body, "https://example.com/invite") {
		t.Errorf("body missing invite link: %q", body)
	}
}
