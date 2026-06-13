package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	logoutCSRFCookieName    = "goauth_oidc_logout_csrf"
	logoutCSRFCookieMaxAgeS = 10 * 60
)

// issueLogoutCSRFCookie generates a random CSRF token, sets it as a cookie scoped
// to /oauth2/logout, and returns the plaintext token for embedding in the form.
//
// Call chain: browserLogoutPage → issueLogoutCSRFCookie → randomLogoutCSRFToken + SetCookie
func issueLogoutCSRFCookie(c *gin.Context, secure bool) (string, error) {
	token, err := randomLogoutCSRFToken()
	if err != nil {
		return "", err
	}

	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(logoutCSRFCookieName, token, logoutCSRFCookieMaxAgeS, "/oauth2/logout", "", secure, true)
	return token, nil
}

// clearLogoutCSRFCookie removes the logout CSRF cookie.
func clearLogoutCSRFCookie(c *gin.Context, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(logoutCSRFCookieName, "", -1, "/oauth2/logout", "", secure, true)
}

// logoutCSRFValid compares the form-submitted CSRF token against the cookie value
// using constant-time comparison.
//
// Call chain: logoutPost → logoutCSRFValid → subtle.ConstantTimeCompare
func logoutCSRFValid(c *gin.Context) bool {
	formToken := strings.TrimSpace(c.PostForm("csrf_token"))
	if formToken == "" {
		return false
	}

	cookieToken, err := c.Cookie(logoutCSRFCookieName)
	if err != nil {
		return false
	}
	cookieToken = strings.TrimSpace(cookieToken)
	if cookieToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(formToken), []byte(cookieToken)) == 1
}

// randomLogoutCSRFToken generates a 32-byte random hex token.
func randomLogoutCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
