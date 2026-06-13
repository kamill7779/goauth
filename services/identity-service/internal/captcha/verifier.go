// Package captcha provides server-side verification for CAPTCHA tokens.
// Supported providers: Cloudflare Turnstile, hCaptcha, Google reCAPTCHA v2/v3.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Provider identifies the CAPTCHA backend.
type Provider string

const (
	ProviderNone      Provider = ""
	ProviderTurnstile Provider = "turnstile"
	ProviderHCaptcha  Provider = "hcaptcha"
	ProviderReCAPTCHA Provider = "recaptcha"
)

var verifyURLs = map[Provider]string{
	ProviderTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	ProviderHCaptcha:  "https://hcaptcha.com/siteverify",
	ProviderReCAPTCHA: "https://www.google.com/recaptcha/api/siteverify",
}

// Verifier validates CAPTCHA tokens from configured providers.
type Verifier struct {
	provider  Provider
	secretKey string
	client    *http.Client
}

// NewVerifier creates a Verifier with a 10-second HTTP timeout.
// If provider is empty, Middleware() returns a no-op handler.
//
// Call chain: wire → NewVerifier
func NewVerifier(provider Provider, secretKey string) *Verifier {
	return &Verifier{
		provider:  provider,
		secretKey: secretKey,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether CAPTCHA verification is configured.
func (v *Verifier) Enabled() bool {
	return v != nil && v.provider != ProviderNone
}

// Middleware returns a Gin middleware that validates CAPTCHA tokens from the
// X-Captcha-Token header or captcha_token query parameter.
// If the provider is not enabled, returns a no-op handler.
//
// Call chain: router setup → Middleware → verify → provider siteverify API
func (v *Verifier) Middleware() gin.HandlerFunc {
	if !v.Enabled() {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		token := strings.TrimSpace(c.GetHeader("X-Captcha-Token"))
		if token == "" {
		// Fall back to the captcha_token query parameter.
			token = strings.TrimSpace(c.Query("captcha_token"))
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "captcha token required",
			})
			return
		}

		if err := v.verify(c.Request.Context(), token, c.ClientIP()); err != nil {
			slog.Warn("captcha verification failed", "error", err, "provider", v.provider)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "captcha verification failed",
			})
			return
		}
		c.Next()
	}
}

type verifyResponse struct {
	Success bool `json:"success"`
}

// verify POSTs the token to the configured provider's siteverify endpoint and
// checks the success flag in the JSON response.
//
// Call chain: Middleware → verify → HTTP POST → json.Unmarshal
func (v *Verifier) verify(ctx context.Context, token, remoteIP string) error {
	verifyURL, ok := verifyURLs[v.provider]
	if !ok {
		return fmt.Errorf("unsupported captcha provider: %s", v.provider)
	}

	form := url.Values{}
	form.Set("secret", v.secretKey)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha provider returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result verifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if !result.Success {
		return &VerificationError{Provider: string(v.provider)}
	}
	return nil
}

// VerificationError is returned when the CAPTCHA provider rejects the token.
type VerificationError struct {
	Provider string
}

func (e *VerificationError) Error() string {
	return "captcha verification failed for provider: " + e.Provider
}

// ActionSet builds a lowercase lookup set from a list of action names, trimming
// whitespace and skipping empty entries.
//
// Call chain: caller → ActionSet → (pure function, no dependencies)
func ActionSet(actions []string) map[string]struct{} {
	result := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		action = strings.ToLower(strings.TrimSpace(action))
		if action == "" {
			continue
		}
		result[action] = struct{}{}
	}
	return result
}
