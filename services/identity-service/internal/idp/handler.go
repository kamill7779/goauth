package idp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	stdhttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/captcha"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
)

const (
	githubOAuthStateCookieName    = "goauth_github_oauth_state"
	githubOAuthStateCookieMaxAgeS = 10 * 60
	oauthStateFlowBind            = "bind"
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
	captchaVerifier      *captcha.Verifier
	captchaActions       map[string]struct{}
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
		captchaActions:       captchaActionSet([]string{"login"}),
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

func (h *Handler) SetCaptchaVerifier(v *captcha.Verifier) {
	h.captchaVerifier = v
}

func (h *Handler) SetCaptchaActions(actions []string) {
	h.captchaActions = captchaActionSet(actions)
}

func (h *Handler) captchaMW() gin.HandlerFunc {
	if h.captchaVerifier == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return h.captchaVerifier.Middleware()
}

func (h *Handler) captchaMWFor(action string) gin.HandlerFunc {
	if !h.captchaActionEnabled(action) {
		return func(c *gin.Context) { c.Next() }
	}
	return h.captchaMW()
}

func (h *Handler) captchaActionEnabled(action string) bool {
	if h.captchaVerifier == nil || !h.captchaVerifier.Enabled() {
		return false
	}
	_, ok := h.captchaActions[strings.ToLower(strings.TrimSpace(action))]
	return ok
}

func captchaActionSet(actions []string) map[string]struct{} {
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

func (h *Handler) RegisterRoutes(router gin.IRouter) {
	external := router.Group("/v1/external/github")
	external.GET("/start", h.start)
	external.POST("/start", h.captchaMWFor("login"), h.start)
	external.GET("/callback", h.callback)
	external.POST("/exchange", h.exchange)

	protected := router.Group("/v1")
	if h.authMiddleware != nil {
		protected.Use(h.authMiddleware)
	}
	protected.POST("/external/github/bind", h.bind)
	protected.DELETE("/external/github/bind", h.unbind)
	protected.POST("/account/login-methods/:provider/bind/start", h.startAccountBind)
	protected.DELETE("/account/login-methods/:provider", h.unbindAccountProvider)
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
	if c.Request.Method == stdhttp.MethodGet && h.captchaActionEnabled("login") {
		c.JSON(stdhttp.StatusForbidden, gin.H{"error": "captcha token required"})
		return
	}

	input, err := h.startInput(c)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	state, err := h.newState()
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	authURL, err := h.service.Start("github", state, AuthCodeOptions{
		RedirectURI: input.RedirectURI,
	})
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.exchangeStore != nil {
		returnTo, _ := h.normalizeExternalReturnTo(input.ReturnTo)
		if err := h.exchangeStore.SaveOAuthState(c.Request.Context(), state, OAuthStatePayload{ReturnTo: returnTo}); err != nil {
			c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	setGitHubOAuthStateCookie(c, state, h.browserCookieSecure)
	if c.Request.Method == stdhttp.MethodPost {
		httpserver.Success(c, stdhttp.StatusOK, gin.H{"authorize_url": authURL})
		return
	}
	c.Redirect(stdhttp.StatusFound, authURL)
}

func (h *Handler) startInput(c *gin.Context) (struct {
	RedirectURI string `json:"redirect_uri"`
	ReturnTo    string `json:"return_to"`
}, error) {
	var input struct {
		RedirectURI string `json:"redirect_uri"`
		ReturnTo    string `json:"return_to"`
	}
	if c.Request.Method == stdhttp.MethodPost {
		if err := c.ShouldBindJSON(&input); err != nil && !errors.Is(err, io.EOF) {
			return input, err
		}
		return input, nil
	}
	input.RedirectURI = c.Query("redirect_uri")
	input.ReturnTo = c.Query("return_to")
	return input, nil
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
	statePayload, err := h.consumeOAuthState(c.Request.Context(), state)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if statePayload.Flow == oauthStateFlowBind {
		h.completeBindCallback(c, "github", code, state, statePayload)
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
		ReturnTo: statePayload.ReturnTo,
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

func (h *Handler) consumeOAuthState(ctx context.Context, state string) (*OAuthStatePayload, error) {
	if h.exchangeStore == nil {
		return &OAuthStatePayload{}, nil
	}
	payload, err := h.exchangeStore.ConsumeOAuthState(ctx, state)
	if err != nil {
		return nil, err
	}
	return payload, nil
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

func (h *Handler) startAccountBind(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}
	if h.exchangeStore == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "external identity binding unavailable"})
		return
	}
	userID, ok := currentUserID(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}

	var request struct {
		ReturnTo    string `json:"return_to"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := c.ShouldBindJSON(&request); err != nil && c.Request.ContentLength != 0 {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	state, err := h.newState()
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	providerSlug := normalizedProviderSlug(c.Param("provider"))
	authURL, err := h.service.Start(providerSlug, state, AuthCodeOptions{
		RedirectURI: request.RedirectURI,
	})
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	returnTo := "/account?tab=login"
	if normalized, ok := h.normalizeExternalReturnTo(request.ReturnTo); ok {
		returnTo = normalized
	}
	if err := h.exchangeStore.SaveOAuthState(c.Request.Context(), state, OAuthStatePayload{
		Flow:     oauthStateFlowBind,
		UserID:   userID,
		ReturnTo: returnTo,
	}); err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	setGitHubOAuthStateCookie(c, state, h.browserCookieSecure)
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"provider":  providerSlug,
		"start_url": authURL,
	})
}

func (h *Handler) unbindAccountProvider(c *gin.Context) {
	if h.service == nil {
		c.JSON(stdhttp.StatusServiceUnavailable, gin.H{"error": "identity provider service unavailable"})
		return
	}
	userID, ok := currentUserID(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}

	providerSlug := normalizedProviderSlug(c.Param("provider"))
	if err := h.service.Unbind(c.Request.Context(), userID, providerSlug); err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, ErrIdentityNotFound) {
			status = stdhttp.StatusNotFound
		} else if errors.Is(err, ErrOnlyLoginMethod) {
			status = stdhttp.StatusConflict
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"unbound": true})
}

func (h *Handler) completeBindCallback(c *gin.Context, providerSlug, code, state string, payload *OAuthStatePayload) {
	if payload.UserID <= 0 {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid bind state"})
		return
	}
	_, err := h.service.BindWithState(c.Request.Context(), payload.UserID, providerSlug, code, c.Query("redirect_uri"), state)
	if err != nil {
		c.Redirect(stdhttp.StatusFound, externalBindReturnURL(payload.ReturnTo, providerSlug, err))
		return
	}
	c.Redirect(stdhttp.StatusFound, externalBindReturnURL(payload.ReturnTo, providerSlug, nil))
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
		} else if errors.Is(err, ErrOnlyLoginMethod) {
			status = stdhttp.StatusConflict
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

func normalizedProviderSlug(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func externalBindReturnURL(returnTo, provider string, bindErr error) string {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" {
		returnTo = "/account?tab=login"
	}
	parsed, err := url.Parse(returnTo)
	if err != nil {
		returnTo = "/account?tab=login"
		parsed, _ = url.Parse(returnTo)
	}
	values := parsed.Query()
	if bindErr != nil {
		values.Set("external_bind_error", bindErr.Error())
	} else {
		values.Set("external_bind", normalizedProviderSlug(provider))
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
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
