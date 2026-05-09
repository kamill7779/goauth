package oidc

import (
	"fmt"
	"html/template"
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type logoutRequest struct {
	ClientID              string
	PostLogoutRedirectURI string
	SessionID             string
}

func (h *Handler) browserLogoutPage(c *gin.Context, request logoutRequest) {
	csrfToken, err := issueLogoutCSRFCookie(c)
	if err != nil {
		c.String(stdhttp.StatusInternalServerError, "failed to create csrf token")
		return
	}

	c.Data(stdhttp.StatusOK, "text/html; charset=utf-8", []byte(renderBrowserLogoutPage(request, csrfToken)))
}

func renderBrowserLogoutPage(request logoutRequest, csrfToken string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GoAuth Sign Out</title>
</head>
<body style="margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f4f1ea;color:#1f2933;">
  <main style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;">
    <section style="width:min(100%%,420px);background:#fffdf8;border:1px solid #e5dccf;border-radius:18px;padding:32px;box-shadow:0 24px 70px rgba(76,53,24,.12);">
      <p style="margin:0 0 8px;font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:#9a6c30;">GoAuth</p>
      <h1 style="margin:0 0 12px;font-size:28px;">Sign out</h1>
      <p style="margin:0 0 24px;color:#5f6c7b;">Confirm sign out to revoke the current browser SSO session.</p>
      <form method="post" action="/oauth2/logout" style="display:grid;gap:14px;">
        <input type="hidden" name="client_id" value="%s">
        <input type="hidden" name="post_logout_redirect_uri" value="%s">
        <input type="hidden" name="session_id" value="%s">
        <input type="hidden" name="csrf_token" value="%s">
        <button type="submit" style="margin-top:6px;border:0;border-radius:999px;padding:12px 18px;background:#155eef;color:#fff;font:inherit;font-weight:600;cursor:pointer;">Sign out</button>
      </form>
    </section>
  </main>
</body>
</html>`,
		template.HTMLEscapeString(strings.TrimSpace(request.ClientID)),
		template.HTMLEscapeString(strings.TrimSpace(request.PostLogoutRedirectURI)),
		template.HTMLEscapeString(strings.TrimSpace(request.SessionID)),
		template.HTMLEscapeString(strings.TrimSpace(csrfToken)),
	)
}
