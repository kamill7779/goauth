package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	browserLoginCSRFCookieName    = "goauth_browser_login_csrf"
	browserLoginCSRFCookieMaxAgeS = 10 * 60
)

func issueBrowserLoginCSRFCookie(c *gin.Context) (string, error) {
	token, err := randomBrowserLoginCSRFToken()
	if err != nil {
		return "", err
	}

	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(browserLoginCSRFCookieName, token, browserLoginCSRFCookieMaxAgeS, "/oauth2/login", "", true, true)
	return token, nil
}

func clearBrowserLoginCSRFCookie(c *gin.Context) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(browserLoginCSRFCookieName, "", -1, "/oauth2/login", "", true, true)
}

func browserLoginCSRFValid(c *gin.Context) bool {
	formToken := strings.TrimSpace(c.PostForm("csrf_token"))
	if formToken == "" {
		return false
	}

	cookieToken, err := c.Cookie(browserLoginCSRFCookieName)
	if err != nil {
		return false
	}
	cookieToken = strings.TrimSpace(cookieToken)
	if cookieToken == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(formToken), []byte(cookieToken)) == 1
}

func randomBrowserLoginCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
