package auth

import (
	"context"
	"fmt"
	"html/template"
	stdhttp "net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
)

type loginResult struct {
	user        *store.User
	pair        *session.TokenPair
	cookieValue string
}

func (h *Handler) completeLogin(ctx context.Context, input LoginInput) (*loginResult, error) {
	user, err := h.service.Login(ctx, input)
	if err != nil {
		return nil, err
	}
	if h.session == nil {
		return &loginResult{user: user}, nil
	}

	pair, err := h.session.IssueTokens(ctx, session.IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "goauth-web",
	})
	if err != nil {
		return nil, err
	}
	cookieValue, err := h.session.IssueOIDCAuthorizeCookie(*user, 0, pair.SessionID)
	if err != nil {
		return nil, err
	}
	return &loginResult{
		user:        user,
		pair:        pair,
		cookieValue: cookieValue,
	}, nil
}

func (h *Handler) browserLoginPage(c *gin.Context) {
	returnTo, ok := normalizeAuthorizeReturnTarget(c.Query("return_to"))
	if !ok {
		c.String(stdhttp.StatusBadRequest, "invalid return target")
		return
	}

	h.renderBrowserLoginPage(c, stdhttp.StatusOK, returnTo, "")
}

func (h *Handler) browserLoginSubmit(c *gin.Context) {
	returnTo, ok := normalizeAuthorizeReturnTarget(c.PostForm("return_to"))
	if !ok {
		c.String(stdhttp.StatusBadRequest, "invalid return target")
		return
	}
	if !browserLoginCSRFValid(c) {
		h.renderBrowserLoginPage(c, stdhttp.StatusForbidden, returnTo, "invalid csrf token")
		return
	}
	if !h.allowBrowserRateLimit(c, returnTo, loginRateLimitScope, rateLimitKey(c, c.PostForm("email")), loginRateLimitLimit, loginRateLimitWindow) {
		return
	}

	result, err := h.completeLogin(c.Request.Context(), LoginInput{
		Email:    c.PostForm("email"),
		Password: c.PostForm("password"),
	})
	if err != nil {
		statusCode, message := loginErrorResponse(err)
		h.renderBrowserLoginPage(c, statusCode, returnTo, message)
		return
	}
	if result.pair == nil {
		c.String(stdhttp.StatusInternalServerError, "browser login is unavailable")
		return
	}

	clearBrowserLoginCSRFCookie(c)
	session.SetOIDCAuthorizeCookie(c, result.cookieValue, int(h.session.OIDCAuthorizeCookieTTL().Seconds()))
	c.Redirect(stdhttp.StatusFound, returnTo)
}

func (h *Handler) renderBrowserLoginPage(c *gin.Context, statusCode int, returnTo, errorMessage string) {
	csrfToken, err := issueBrowserLoginCSRFCookie(c)
	if err != nil {
		c.String(stdhttp.StatusInternalServerError, "failed to create csrf token")
		return
	}

	c.Data(statusCode, "text/html; charset=utf-8", []byte(renderBrowserLoginPage(returnTo, csrfToken, errorMessage)))
}

func renderBrowserLoginPage(returnTo, csrfToken, errorMessage string) string {
	escapedReturnTo := template.HTMLEscapeString(returnTo)
	escapedCSRF := template.HTMLEscapeString(csrfToken)
	escapedError := template.HTMLEscapeString(strings.TrimSpace(errorMessage))

	var errorBlock string
	if escapedError != "" {
		errorBlock = fmt.Sprintf(`<p style="margin:0 0 16px;padding:12px 14px;border-radius:10px;background:#fdecea;color:#8a1c1c;">%s</p>`, escapedError)
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GoAuth Sign In</title>
</head>
<body style="margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f4f1ea;color:#1f2933;">
  <main style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;">
    <section style="width:min(100%%,420px);background:#fffdf8;border:1px solid #e5dccf;border-radius:18px;padding:32px;box-shadow:0 24px 70px rgba(76,53,24,.12);">
      <p style="margin:0 0 8px;font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:#9a6c30;">GoAuth</p>
      <h1 style="margin:0 0 12px;font-size:28px;">Sign in</h1>
      <p style="margin:0 0 24px;color:#5f6c7b;">Continue to the application by signing in with your GoAuth account.</p>
      %s
      <form method="post" action="/oauth2/login" style="display:grid;gap:14px;">
        <input type="hidden" name="return_to" value="%s">
        <input type="hidden" name="csrf_token" value="%s">
        <label style="display:grid;gap:6px;font-size:14px;">
          <span>Email</span>
          <input type="email" name="email" autocomplete="username" required style="border:1px solid #cdbda7;border-radius:10px;padding:12px 14px;font:inherit;">
        </label>
        <label style="display:grid;gap:6px;font-size:14px;">
          <span>Password</span>
          <input type="password" name="password" autocomplete="current-password" required style="border:1px solid #cdbda7;border-radius:10px;padding:12px 14px;font:inherit;">
        </label>
        <button type="submit" style="margin-top:6px;border:0;border-radius:999px;padding:12px 18px;background:#155eef;color:#fff;font:inherit;font-weight:600;cursor:pointer;">Continue</button>
      </form>
    </section>
  </main>
</body>
</html>`, errorBlock, escapedReturnTo, escapedCSRF)
}

func normalizeAuthorizeReturnTarget(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" {
		return "", false
	}
	if parsed.Path != "/oauth2/authorize" {
		return "", false
	}

	target := parsed.Path
	if parsed.RawQuery != "" {
		target += "?" + parsed.RawQuery
	}
	return target, true
}
