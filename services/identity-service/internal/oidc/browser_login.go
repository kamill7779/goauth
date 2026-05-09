package oidc

import (
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func NormalizeAuthorizeReturnTarget(raw string) (string, bool) {
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

func browserPrefersHTML(c *gin.Context) bool {
	accept := strings.ToLower(c.GetHeader("Accept"))
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

func browserRequestsDocument(c *gin.Context) bool {
	if browserPrefersHTML(c) {
		return true
	}

	mode := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Mode")))
	if mode == "navigate" {
		return true
	}

	dest := strings.ToLower(strings.TrimSpace(c.GetHeader("Sec-Fetch-Dest")))
	return dest == "document"
}

func buildBrowserLoginRedirectPath(loginPath, returnTo string) string {
	query := url.Values{
		"return_to": {returnTo},
	}
	return loginPath + "?" + query.Encode()
}
