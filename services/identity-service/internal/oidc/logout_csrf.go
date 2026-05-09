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

func issueLogoutCSRFCookie(c *gin.Context) (string, error) {
	token, err := randomLogoutCSRFToken()
	if err != nil {
		return "", err
	}

	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(logoutCSRFCookieName, token, logoutCSRFCookieMaxAgeS, "/oauth2/logout", "", true, true)
	return token, nil
}

func clearLogoutCSRFCookie(c *gin.Context) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(logoutCSRFCookieName, "", -1, "/oauth2/logout", "", true, true)
}

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

func randomLogoutCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
