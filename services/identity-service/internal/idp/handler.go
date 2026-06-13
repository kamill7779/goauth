package idp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

// HandlerDeps bundles optional dependencies for the IDP handler.
type HandlerDeps struct {
	CaptchaVerifier        *captcha.Verifier
	CaptchaActions         []string
	FrontendCallbackPath   string
	TrustedReturnToOrigins []string
	ExchangeStore          *ExchangeStore
}

// SetDeps injects optional dependencies.
func (h *Handler) SetDeps(d HandlerDeps) {
	h.captchaVerifier = d.CaptchaVerifier
	if len(d.CaptchaActions) > 0 {
		h.captchaActions = captcha.ActionSet(d.CaptchaActions)
	}
	if p := strings.TrimSpace(d.FrontendCallbackPath); p != "" {
		h.frontendCallbackPath = p
	}
	if len(d.TrustedReturnToOrigins) > 0 {
		h.trustedReturnOrigins = buildTrustedOriginSet(d.TrustedReturnToOrigins)
	}
	h.exchangeStore = d.ExchangeStore
}

// buildTrustedOriginSet canonicalises a list of URL strings into a set of
// "scheme://host" keys for fast lookup.
//
// Call chain: SetDeps → buildTrustedOriginSet
func buildTrustedOriginSet(origins []string) map[string]struct{} {
	set := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		if o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil {
			continue
		}
		set[fmt.Sprintf("%s://%s", u.Scheme, u.Host)] = struct{}{}
	}
	return set
}

// NewHandler creates an IDP Handler with sensible defaults.
//
// Call chain: wire (DI) → NewHandler → registers routes on gin router
func NewHandler(service *Service, sessions SessionIssuer, authMiddleware gin.HandlerFunc, browserCookieSecure bool) *Handler {
	return &Handler{
		service:              service,
		sessions:             sessions,
		authMiddleware:       authMiddleware,
		captchaActions:       captcha.ActionSet([]string{"login"}),
		browserCookieSecure:  browserCookieSecure,
		newState:             randomState,
		frontendCallbackPath: "/external/callback",
	}
}

// SetExchangeStore sets the exchange store.
func (h *Handler) SetExchangeStore(store *ExchangeStore) {
	h.exchangeStore = store
}

// SetFrontendCallbackPath sets the frontend callback path used after OAuth
// completion; defaults to /external/callback when empty.
//
// Call chain: wire (DI) → SetFrontendCallbackPath
func (h *Handler) SetFrontendCallbackPath(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/external/callback"
	}
	h.frontendCallbackPath = path
}

// SetTrustedReturnToOrigins configures which external origins are allowed as
// return_to targets after an OAuth flow.
//
// Call chain: wire (DI) → SetTrustedReturnToOrigins
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

// SetCaptchaVerifier sets the captcha verifier.
func (h *Handler) SetCaptchaVerifier(v *captcha.Verifier) {
	h.captchaVerifier = v
}

// SetCaptchaActions sets the captcha-protected actions.
func (h *Handler) SetCaptchaActions(actions []string) {
	h.captchaActions = captcha.ActionSet(actions)
}

// captchaMW returns a gin middleware that validates captcha if configured,
// otherwise a no-op passthrough.
//
// Call chain: captchaMWFor → captchaMW → captcha.Verifier.Middleware
func (h *Handler) captchaMW() gin.HandlerFunc {
	if h.captchaVerifier == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return h.captchaVerifier.Middleware()
}

// captchaMWFor returns a captcha middleware gated on the named action being
// enabled; falls back to a no-op when the action is not protected.
//
// Call chain: route registration → captchaMWFor → captchaMW
func (h *Handler) captchaMWFor(action string) gin.HandlerFunc {
	if !h.captchaActionEnabled(action) {
		return func(c *gin.Context) { c.Next() }
	}
	return h.captchaMW()
}

// captchaActionEnabled reports whether the given action is configured for
// captcha protection.
//
// Call chain: route handlers / captchaMWFor → captchaActionEnabled
func (h *Handler) captchaActionEnabled(action string) bool {
	if h.captchaVerifier == nil || !h.captchaVerifier.Enabled() {
		return false
	}
	_, ok := h.captchaActions[strings.ToLower(strings.TrimSpace(action))]
	return ok
}


// RegisterRoutes wires idp endpoints onto the provided gin router.
//
// Call chain: HTTP router setup → RegisterRoutes → individual handlers
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

// start initiates the GitHub OAuth authorization-code flow. On GET it
// redirects to GitHub; on POST it returns the authorize URL as JSON.
//
// Call chain: POST/GET /v1/external/github/start → start → service.Start → provider.AuthCodeURL
func (h *Handler) start(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}
	if h.browserExchangeUnavailable() {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "external login exchange unavailable")
		return
	}
	if c.Request.Method == stdhttp.MethodGet && h.captchaActionEnabled("login") {
		httpserver.Error(c, stdhttp.StatusForbidden, "captcha token required")
		return
	}

	input, err := h.startInput(c)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	state, err := h.newState()
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}

	authURL, err := h.service.Start("github", state, AuthCodeOptions{
		RedirectURI: input.RedirectURI,
	})
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	if h.exchangeStore != nil {
		returnTo, _ := h.normalizeExternalReturnTo(input.ReturnTo)
		if err := h.exchangeStore.SaveOAuthState(c.Request.Context(), state, OAuthStatePayload{ReturnTo: returnTo}); err != nil {
			httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
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

// startInput extracts authorization-request parameters from either JSON body
// (POST) or query string (GET).
//
// Call chain: start → startInput
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

// callback handles the GitHub OAuth redirect. It validates the state
// parameter against the cookie, exchanges the code for a profile, issues
// session tokens, and redirects to the frontend with an exchange code.
//
// Call chain: GET /v1/external/github/callback → callback → service.Authenticate → sessions.IssueTokens → exchangeStore.Save
func (h *Handler) callback(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}
	if h.browserExchangeUnavailable() {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "external login exchange unavailable")
		return
	}

	code := c.Query("code")
	if code == "" {
		httpserver.Error(c, stdhttp.StatusBadRequest, "missing code")
		return
	}

	stateCookie, err := c.Cookie(githubOAuthStateCookieName)
	if err != nil || strings.TrimSpace(stateCookie) == "" {
		httpserver.Error(c, stdhttp.StatusBadRequest, "invalid state")
		return
	}
	state := strings.TrimSpace(c.Query("state"))
	if state == "" || state != strings.TrimSpace(stateCookie) {
		httpserver.Error(c, stdhttp.StatusBadRequest, "invalid state")
		return
	}
	defer clearGitHubOAuthStateCookie(c, h.browserCookieSecure)
	statePayload, err := h.consumeOAuthState(c.Request.Context(), state)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
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
		httpserver.Error(c, status, err.Error())
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
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	cookieValue, err := h.sessions.IssueOIDCAuthorizeCookieBySessionID(c.Request.Context(), pair.SessionID)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	session.SetOIDCAuthorizeCookie(c, cookieValue, int(h.sessions.OIDCAuthorizeCookieTTL().Seconds()), h.browserCookieSecure)

	if h.exchangeStore == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "external login exchange unavailable")
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
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	c.Redirect(stdhttp.StatusFound, h.frontendExchangeURL(code))
}

// exchange consumes a short-lived exchange code and returns the cached token
// pair and user payload to the frontend.
//
// Call chain: POST /v1/external/github/exchange → exchange → exchangeStore.Consume
func (h *Handler) exchange(c *gin.Context) {
	if h.exchangeStore == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "external login exchange unavailable")
		return
	}

	var request struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	payload, err := h.exchangeStore.Consume(c.Request.Context(), request.Code)
	if errors.Is(err, ErrExchangeCodeInvalid) {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, payload)
}

// consumeOAuthState reads and deletes the OAuth state payload from the
// exchange store. When no store is configured it returns an empty payload.
//
// Call chain: callback → consumeOAuthState → exchangeStore.ConsumeOAuthState
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

// frontendExchangeURL builds the frontend callback URL with exchange code
// and provider set as the fragment.
//
// Call chain: callback → frontendExchangeURL
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

// browserExchangeUnavailable returns true when sessions are configured but
// the exchange store (Redis) is not, meaning the browser-based OAuth flow
// cannot complete.
func (h *Handler) browserExchangeUnavailable() bool {
	return h.sessions != nil && h.exchangeStore == nil
}

// startAccountBind initiates an OAuth flow for binding an external identity
// to the currently authenticated account. It persists flow=bind in the OAuth
// state so the callback knows to link rather than authenticate.
//
// Call chain: POST /v1/account/login-methods/:provider/bind/start → startAccountBind → service.Start → exchangeStore.SaveOAuthState
func (h *Handler) startAccountBind(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}
	if h.exchangeStore == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "external identity binding unavailable")
		return
	}
	userID, ok := currentUserID(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}

	var request struct {
		ReturnTo    string `json:"return_to"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := c.ShouldBindJSON(&request); err != nil && c.Request.ContentLength != 0 {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	state, err := h.newState()
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	providerSlug := normalizedProviderSlug(c.Param("provider"))
	authURL, err := h.service.Start(providerSlug, state, AuthCodeOptions{
		RedirectURI: request.RedirectURI,
	})
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
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
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}

	setGitHubOAuthStateCookie(c, state, h.browserCookieSecure)
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"provider":  providerSlug,
		"start_url": authURL,
	})
}

// unbindAccountProvider removes a linked external identity from the current
// user, preventing lock-out by verifying at least one login method remains.
//
// Call chain: DELETE /v1/account/login-methods/:provider → unbindAccountProvider → service.Unbind
func (h *Handler) unbindAccountProvider(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}
	userID, ok := currentUserID(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
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
		httpserver.Error(c, status, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"unbound": true})
}

// completeBindCallback finishes the OAuth bind flow after the provider
// redirects back; it calls service.BindWithState and redirects to the
// frontend with success/error flags.
//
// Call chain: callback (flow=bind) → completeBindCallback → service.BindWithState
func (h *Handler) completeBindCallback(c *gin.Context, providerSlug, code, state string, payload *OAuthStatePayload) {
	if payload.UserID <= 0 {
		httpserver.Error(c, stdhttp.StatusBadRequest, "invalid bind state")
		return
	}
	_, err := h.service.BindWithState(c.Request.Context(), payload.UserID, providerSlug, code, c.Query("redirect_uri"), state)
	if err != nil {
		c.Redirect(stdhttp.StatusFound, externalBindReturnURL(payload.ReturnTo, providerSlug, err))
		return
	}
	c.Redirect(stdhttp.StatusFound, externalBindReturnURL(payload.ReturnTo, providerSlug, nil))
}

// bind links an external GitHub identity to an already-authenticated user
// using an authorization code obtained on the frontend.
//
// Call chain: POST /v1/external/github/bind → bind → service.Bind
func (h *Handler) bind(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}

	var request struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	if request.Code == "" {
		httpserver.Error(c, stdhttp.StatusBadRequest, "missing code")
		return
	}

	identity, err := h.service.Bind(c.Request.Context(), userID, "github", request.Code, request.RedirectURI)
	if err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, ErrExternalIdentityInUse) || errors.Is(err, ErrProviderAlreadyBound) {
			status = stdhttp.StatusConflict
		}
		httpserver.Error(c, status, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, identity)
}

// unbind removes the GitHub identity from the authenticated user.
//
// Call chain: DELETE /v1/external/github/bind → unbind → service.Unbind
func (h *Handler) unbind(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}

	if err := h.service.Unbind(c.Request.Context(), userID, "github"); err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, ErrIdentityNotFound) {
			status = stdhttp.StatusNotFound
		} else if errors.Is(err, ErrOnlyLoginMethod) {
			status = stdhttp.StatusConflict
		}
		httpserver.Error(c, status, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"unbound": true})
}

// listIdentities returns all external identities linked to the authenticated
// user.
//
// Call chain: GET /v1/me/identities → listIdentities → service.ListIdentities
func (h *Handler) listIdentities(c *gin.Context) {
	if h.service == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "identity provider service unavailable")
		return
	}

	userID, ok := currentUserID(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}

	identities, err := h.service.ListIdentities(c.Request.Context(), userID)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, identities)
}

// normalizedProviderSlug returns a lowercased, trimmed provider identifier.
func normalizedProviderSlug(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

// externalBindReturnURL builds the redirect URL returned to the frontend
// after an external identity bind flow, attaching success/error parameters.
//
// Call chain: completeBindCallback → externalBindReturnURL
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

// currentUserID extracts the authenticated user ID from session claims stored
// in the gin context.
//
// Call chain: route handlers → currentUserID → session.ClaimsFromContext
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

// normalizeExternalReturnTo validates that raw is a relative path (or
// absolute path with no host) suitable for a frontend redirect; rejects
// fully-qualified URLs.
//
// Call chain: start / startAccountBind → normalizeExternalReturnTo
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

// normalizeExternalReturnTo extends the package-level check by also allowing
// trusted third-party origins whose path is /oauth2/authorize.
//
// Call chain: start / startAccountBind → h.normalizeExternalReturnTo → canonicalOrigin
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

// canonicalOrigin extracts the lowercased "scheme://host" from a URL string.
// Returns false when the input is not a valid absolute URL.
//
// Call chain: SetTrustedReturnToOrigins / h.normalizeExternalReturnTo → canonicalOrigin
func canonicalOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), true
}

// randomState generates a hex-encoded 128-bit random value for OAuth state.
//
// Call chain: start / startAccountBind → randomState
func randomState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// setGitHubOAuthStateCookie stores the OAuth state in a browser cookie.
func setGitHubOAuthStateCookie(c *gin.Context, value string, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(githubOAuthStateCookieName, value, githubOAuthStateCookieMaxAgeS, "/", "", secure, true)
}

// clearGitHubOAuthStateCookie removes the OAuth state cookie.
func clearGitHubOAuthStateCookie(c *gin.Context, secure bool) {
	c.SetSameSite(stdhttp.SameSiteLaxMode)
	c.SetCookie(githubOAuthStateCookieName, "", -1, "/", "", secure, true)
}
