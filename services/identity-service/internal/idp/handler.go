package idp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	IssueOIDCAuthorizeCookieBySessionID(ctx context.Context, sessionID string) (string, error)
	OIDCAuthorizeCookieTTL() time.Duration
}

type Handler struct {
	service              *Service
	sessions             SessionIssuer
	authMiddleware       gin.HandlerFunc
	browserCookieSecure  bool
	newState             func() (string, error)
	exchangeStore        *ExchangeStore
	frontendCallbackPath string
	trustedReturnOrigins map[string]struct{}
}

func NewHandler(service *Service, sessions SessionIssuer, authMiddleware gin.HandlerFunc, browserCookieSecure bool) *Handler {
	return &Handler{
		service:              service,
		sessions:             sessions,
		authMiddleware:       authMiddleware,
		browserCookieSecure:  browserCookieSecure,
		newState:             randomState,
		frontendCallbackPath: "/external/callback",
	}
}

func (h *Handler) SetExchangeStore(store *ExchangeStore) {
	h.exchangeStore = store
}

func (h *Handler) SetFrontendCallbackPath(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/external/callback"
	}
	h.frontendCallbackPath = path
}

func (h *Handler) SetTrustedReturnToOrigins(origins ...string) {
	h.trustedReturnOrigins = make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		canonical, ok := canonicalOrigin(origin)
		if !ok {
			continue
		}
		h.trustedReturnOrigins[canonical] = struct{}{}
	}
}

func (h *Handler) RegisterRoutes(router gin.IRouter) {
	external := router.Group("/v1/external/github")
	external.GET("/start", h.start)
	external.GET("/callback", h.callback)
	external.POST("/exchange", h.exchange)

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
	if h.browserExchangeUnavailable() {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "external login exchange unavailable"})
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

	if h.exchangeStore != nil {
		returnTo, _ := h.normalizeExternalReturnTo(c.Query("return_to"))
		if err := h.exchangeStore.SaveOAuthState(c.Request.Context(), state, OAuthStatePayload{ReturnTo: returnTo}); err != nil {
			c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	setGitHubOAuthStateCookie(c, state, h.browserCookieSecure)
	c.Redirect(stdhttp.StatusFound, authURL)
}

func (h *Handler) callback(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}
	if h.browserExchangeUnavailable() {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "external login exchange unavailable"})
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
	defer clearGitHubOAuthStateCookie(c, h.browserCookieSecure)
	returnTo, err := h.consumeReturnTo(c.Request.Context(), state)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	result, err := h.service.AuthenticateWithState(c.Request.Context(), "github", code, c.Query("redirect_uri"), state)
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
	cookieValue, err := h.sessions.IssueOIDCAuthorizeCookieBySessionID(c.Request.Context(), pair.SessionID)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	session.SetOIDCAuthorizeCookie(c, cookieValue, int(h.sessions.OIDCAuthorizeCookieTTL().Seconds()), h.browserCookieSecure)

	if h.exchangeStore == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "external login exchange unavailable"})
		return
	}
	code, err = h.exchangeStore.Save(c.Request.Context(), ExchangePayload{
		Provider: "github",
		Tokens:   *pair,
		User: ExchangeUser{
			ID:    result.User.ID,
			Email: result.User.Email,
		},
		ReturnTo: returnTo,
	})
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Redirect(stdhttp.StatusFound, h.frontendExchangeURL(code))
}

func (h *Handler) exchange(c *gin.Context) {
	if h.exchangeStore == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "external login exchange unavailable"})
		return
	}

	var request struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	payload, err := h.exchangeStore.Consume(c.Request.Context(), request.Code)
	if errors.Is(err, ErrExchangeCodeInvalid) {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, payload)
}

func (h *Handler) consumeReturnTo(ctx context.Context, state string) (string, error) {
	if h.exchangeStore == nil {
		return "", nil
	}
	payload, err := h.exchangeStore.ConsumeOAuthState(ctx, state)
	if err != nil {
		return "", err
	}
	return payload.ReturnTo, nil
}

func (h *Handler) frontendExchangeURL(code string) string {
	values := url.Values{}
	values.Set("code", code)
	values.Set("provider", "github")
	callback := strings.TrimSpace(h.frontendCallbackPath)
	if callback == "" {
		callback = "/external/callback"
	}
	parsed, err := url.Parse(callback)
	if err != nil {
		return "/external/callback#" + values.Encode()
	}
	parsed.Fragment = values.Encode()
	return parsed.String()
}

func (h *Handler) browserExchangeUnavailable() bool {
	return h.sessions != nil && h.exchangeStore == nil
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

func normalizeExternalReturnTo(raw string) (string, bool) {
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
	if parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "", false
	}
	target := parsed.Path
	if parsed.RawQuery != "" {
		target += "?" + parsed.RawQuery
	}
	return target, true
}

func (h *Handler) normalizeExternalReturnTo(raw string) (string, bool) {
	if target, ok := normalizeExternalReturnTo(raw); ok {
		return target, true
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return "", false
	}
	if parsed.Path != "/oauth2/authorize" {
		return "", false
	}
	canonical, ok := canonicalOrigin(parsed.String())
	if !ok {
		return "", false
	}
	if _, trusted := h.trustedReturnOrigins[canonical]; !trusted {
		return "", false
	}
	target := parsed.Scheme + "://" + parsed.Host + parsed.Path
	if parsed.RawQuery != "" {
		target += "?" + parsed.RawQuery
	}
	return target, true
}

func canonicalOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

func randomState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func setGitHubOAuthStateCookie(c *gin.Context, value string, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(githubOAuthStateCookieName, value, githubOAuthStateCookieMaxAgeS, "/", "", secure, true)
}

func clearGitHubOAuthStateCookie(c *gin.Context, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(githubOAuthStateCookieName, "", -1, "/", "", secure, true)
}
