package idp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
)

const (
	githubOAuthStateCookieName    = "goauth_github_oauth_state"
	githubOAuthStateCookieMaxAgeS = 10 * 60
)

type SessionIssuer interface {
	IssueTokens(ctx context.Context, input session.IssueTokensInput) (*session.TokenPair, error)
}

type Handler struct {
	service        *Service
	sessions       SessionIssuer
	authMiddleware gin.HandlerFunc
	newState       func() (string, error)
}

func NewHandler(service *Service, sessions SessionIssuer, authMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		service:        service,
		sessions:       sessions,
		authMiddleware: authMiddleware,
		newState:       randomState,
	}
}

func (h *Handler) RegisterRoutes(router gin.IRouter) {
	external := router.Group("/v1/external/github")
	external.GET("/start", h.start)
	external.GET("/callback", h.callback)

	protected := router.Group("/v1")
	if h.authMiddleware != nil {
		protected.Use(h.authMiddleware)
	}
	protected.POST("/external/github/bind", h.bind)
	protected.DELETE("/external/github/bind", h.unbind)
	protected.GET("/me/identities", h.listIdentities)
}

func (h *Handler) start(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}

	state, err := h.newState()
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	authURL, err := h.service.Start("github", state, AuthCodeOptions{
		RedirectURI: c.Query("redirect_uri"),
	})
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	setGitHubOAuthStateCookie(c, state)
	c.Redirect(stdhttp.StatusFound, authURL)
}

func (h *Handler) callback(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	stateCookie, err := c.Cookie(githubOAuthStateCookieName)
	if err != nil || strings.TrimSpace(stateCookie) == "" {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}
	state := strings.TrimSpace(c.Query("state"))
	if state == "" || state != strings.TrimSpace(stateCookie) {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}
	defer clearGitHubOAuthStateCookie(c)

	result, err := h.service.Authenticate(c.Request.Context(), "github", code, c.Query("redirect_uri"))
	if err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, ErrLocalLoginRequired) {
			status = stdhttp.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if h.sessions == nil {
		httpserver.Success(c, stdhttp.StatusOK, gin.H{
			"user":     result.User,
			"identity": result.Identity,
			"created":  result.Created,
		})
		return
	}

	pair, err := h.sessions.IssueTokens(c.Request.Context(), session.IssueTokensInput{
		User:     *result.User,
		TenantID: 0,
		ClientID: "github-oauth",
	})
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"tokens":   pair,
		"user":     result.User,
		"identity": result.Identity,
		"created":  result.Created,
	})
}

func (h *Handler) bind(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}

	var request struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.Code == "" {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "missing code"})
		return
	}

	identity, err := h.service.Bind(c.Request.Context(), userID, "github", request.Code, request.RedirectURI)
	if err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, ErrExternalIdentityInUse) || errors.Is(err, ErrProviderAlreadyBound) {
			status = stdhttp.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, identity)
}

func (h *Handler) unbind(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}

	if err := h.service.Unbind(c.Request.Context(), userID, "github"); err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, ErrIdentityNotFound) {
			status = stdhttp.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"unbound": true})
}

func (h *Handler) listIdentities(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}

	identities, err := h.service.ListIdentities(c.Request.Context(), userID)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, identities)
}

func currentUserID(c *gin.Context) (int64, bool) {
	claims, ok := session.ClaimsFromContext(c)
	if !ok {
		return 0, false
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, false
	}
	return userID, true
}

func randomState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func setGitHubOAuthStateCookie(c *gin.Context, value string) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(githubOAuthStateCookieName, value, githubOAuthStateCookieMaxAgeS, "/", "", true, true)
}

func clearGitHubOAuthStateCookie(c *gin.Context) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(githubOAuthStateCookieName, "", -1, "/", "", true, true)
}
