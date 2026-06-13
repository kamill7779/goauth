// Package auth implements self-service authentication flows: registration,
// login (with lockout), email verification codes, and password reset.
package auth

import (
	"errors"
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/captcha"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/ratelimit"
	"goauth/services/identity-service/internal/session"
)

// Handler exposes HTTP endpoints for self-service auth: send-code, register,
// login, 2FA verification, forgot-password, and reset-password. It wires the
// auth Service with session management, rate limiting, and CAPTCHA.
//
// Routes: POST /email/send-code, /register, /login, /password/forgot, /password/reset
type Handler struct {
	service         *Service
	session         *session.Service
	rateLimiter     *ratelimit.Service
	captchaVerifier *captcha.Verifier
	captchaActions  map[string]struct{}

	registrationMode          string
	localPasswordLoginEnabled bool
}

// HandlerDeps bundles optional dependencies for the auth handler.
type HandlerDeps struct {
	RateLimiter               *ratelimit.Service
	CaptchaVerifier           *captcha.Verifier
	CaptchaActions            []string
	RegistrationMode          string
	LocalPasswordLoginEnabled *bool
}

// SetDeps injects optional dependencies.
func (h *Handler) SetDeps(d HandlerDeps) {
	h.rateLimiter = d.RateLimiter
	h.captchaVerifier = d.CaptchaVerifier
	if len(d.CaptchaActions) > 0 {
		h.captchaActions = captcha.ActionSet(d.CaptchaActions)
	}
	if mode := strings.TrimSpace(d.RegistrationMode); mode != "" {
		h.registrationMode = strings.ToLower(mode)
	}
	if d.LocalPasswordLoginEnabled != nil {
		h.localPasswordLoginEnabled = *d.LocalPasswordLoginEnabled
	}
}

var defaultCaptchaActions = []string{"login", "register", "email_code", "password_forgot"}

// NewHandler creates an auth Handler wired to the given auth and session services.
//
// Call chain: main → NewHandler → register routes on gin.Engine
func NewHandler(service *Service, sessionService *session.Service) *Handler {
	return &Handler{
		service:                   service,
		session:                   sessionService,
		captchaActions:            captcha.ActionSet(defaultCaptchaActions),
		registrationMode:          "open",
		localPasswordLoginEnabled: true,
	}
}

// SetRegistrationMode configures how new accounts can be created (e.g. "open", "invite").
func (h *Handler) SetRegistrationMode(mode string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "open"
	}
	h.registrationMode = mode
}

// SetLocalPasswordLoginEnabled toggles whether local-credential login is available.
func (h *Handler) SetLocalPasswordLoginEnabled(enabled bool) {
	h.localPasswordLoginEnabled = enabled
}

// SetCaptchaVerifier injects a CAPTCHA verifier for automated-abuse protection.
func (h *Handler) SetCaptchaVerifier(v *captcha.Verifier) {
	h.captchaVerifier = v
}

// SetCaptchaActions sets which handler actions require CAPTCHA verification.
func (h *Handler) SetCaptchaActions(actions []string) {
	h.captchaActions = captcha.ActionSet(actions)
}

// captchaMW returns a noop middleware when no CAPTCHA verifier is configured.
//
// Call chain: captchaMWFor → captchaMW → verifier.Middleware
func (h *Handler) captchaMW() gin.HandlerFunc {
	if h.captchaVerifier == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return h.captchaVerifier.Middleware()
}

// captchaMWFor returns a CAPTCHA middleware only when the action is gated.
//
// Call chain: RegisterRoutes → captchaMWFor → captchaMW
func (h *Handler) captchaMWFor(action string) gin.HandlerFunc {
	if !h.captchaActionEnabled(action) {
		return func(c *gin.Context) { c.Next() }
	}
	return h.captchaMW()
}

// captchaActionEnabled reports whether CAPTCHA is active for the given action.
func (h *Handler) captchaActionEnabled(action string) bool {
	if h.captchaVerifier == nil || !h.captchaVerifier.Enabled() {
		return false
	}
	_, ok := h.captchaActions[strings.ToLower(strings.TrimSpace(action))]
	return ok
}

// RegisterRoutes mounts auth endpoints onto the given router group.
//
// Call chain: main → RegisterRoutes → captchaMWFor → handler methods
func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.POST("/email/send-code", h.captchaMWFor("email_code"), h.sendCode)
	router.POST("/register", h.captchaMWFor("register"), h.register)
	router.POST("/login", h.captchaMWFor("login"), h.login)
	router.POST("/login/2fa/verify", h.loginTwoFactorVerify)
	router.POST("/password/forgot", h.captchaMWFor("password_forgot"), h.forgotPassword)
	router.POST("/password/reset", h.resetPassword)
}


// sendCode sends a one-time verification code to the specified email address.
//
// Call chain: POST /email/send-code → sendCode → service.SendEmailCode → Redis + mailer
//
// @Summary      Send verification code
// @Description  Sends a 6-digit verification code for registration or password reset.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  object{purpose=string,email=string}  true  "Request body"
// @Success      200   {object}  object{sent=bool}
// @Failure      400   {object}  object
// @Failure      403   {object}  object  "registration disabled"
// @Failure      429   {object}  object  "rate limited"
// @Router       /v1/auth/email/send-code [post]
func (h *Handler) sendCode(c *gin.Context) {
	var request struct {
		Purpose string `json:"purpose"`
		Email   string `json:"email"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	purpose, err := normalizeEmailCodePurpose(request.Purpose)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	if purpose == EmailCodePurposeRegister && h.registrationMode != "open" {
		httpserver.Error(c, stdhttp.StatusForbidden, "registration disabled")
		return
	}
	if !h.allowJSONRateLimit(c, emailCodeRateLimitScope, rateLimitEmailCodeKey(c, purpose, request.Email), emailCodeRateLimitLimit, emailCodeRateLimitWindow) {
		return
	}
	if _, err := h.service.SendEmailCode(c.Request.Context(), purpose, request.Email); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"sent": true})
}

// register creates a new user account after email verification.
//
// Call chain: POST /register → register → service.Register → repo.Create + policy.Apply
//
// @Summary      Register new user
// @Description  Creates a new user account. Requires a valid email verification code obtained via /email/send-code.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  object{username=string,email=string,password=string,email_code=string,display_name=string}  true  "Registration data"
// @Success      200   {object}  object{id=int,email=string}
// @Failure      400   {object}  object  "invalid input or email code"
// @Failure      403   {object}  object  "registration disabled"
// @Router       /v1/auth/register [post]
func (h *Handler) register(c *gin.Context) {
	if h.registrationMode != "open" {
		httpserver.Error(c, stdhttp.StatusForbidden, "registration disabled")
		return
	}

	var request struct {
		Username    string `json:"username"`
		Nickname    string `json:"nickname"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		EmailCode   string `json:"email_code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	user, err := h.service.Register(c.Request.Context(), RegisterInput{
		Username:    request.Username,
		Nickname:    request.Nickname,
		Email:       request.Email,
		DisplayName: request.DisplayName,
		Password:    request.Password,
		EmailCode:   request.EmailCode,
		CodePurpose: EmailCodePurposeRegister,
	})
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusCreated, gin.H{
		"id":    user.ID,
		"email": user.Email,
	})
}

// login authenticates a user with email and password.
//
// Call chain: POST /login → login → completeLogin → service.Login + 2FA check + issueLoginTokens
//
// @Summary      Login
// @Description  Authenticates with email/password. Returns access token, refresh token, and session info. May require 2FA verification.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  object{email=string,password=string}  true  "Login credentials"
// @Success      200   {object}  object{access_token=string,refresh_token=string,sid=string,user_id=int64,email=string}
// @Failure      400   {object}  object
// @Failure      401   {object}  object  "invalid credentials"
// @Failure      423   {object}  object  "account locked"
// @Router       /v1/auth/login [post]
func (h *Handler) login(c *gin.Context) {
	if !h.localPasswordLoginEnabled {
		httpserver.Error(c, stdhttp.StatusForbidden, "local password login disabled")
		return
	}

	var request struct {
		Identifier string `json:"identifier"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	rlKey := request.Identifier
	if rlKey == "" {
		rlKey = request.Email
	}
	if !h.allowJSONRateLimit(c, loginRateLimitScope, rateLimitKey(c, rlKey), loginRateLimitLimit, loginRateLimitWindow) {
		return
	}

	result, err := h.completeLogin(c.Request.Context(), LoginInput{
		Identifier: request.Identifier,
		Email:      request.Email,
		Password:   request.Password,
	})
	if err != nil {
		statusCode, message := loginErrorResponse(err)
		var lockoutErr *LockoutError
		if errors.As(err, &lockoutErr) {
			ratelimit.SetRetryAfterHeader(c, lockoutErr.RetryAfter)
		}
		httpserver.Error(c, statusCode, message)
		return
	}

	if result.pair == nil {
		if result.twoFactor != nil {
			httpserver.Success(c, stdhttp.StatusOK, gin.H{
				"id":                  result.user.ID,
				"email":               result.user.Email,
				"two_factor_required": true,
				"challenge_id":        result.twoFactor.ID,
				"expires_in":          result.twoFactor.ExpiresIn,
				"methods":             []string{"totp", "recovery_code"},
			})
			return
		}
		httpserver.Success(c, stdhttp.StatusOK, gin.H{
			"id":    result.user.ID,
			"email": result.user.Email,
		})
		return
	}

	if h.session != nil {
		h.session.SetOIDCAuthorizeCookie(c, result.cookieValue, int(h.session.OIDCAuthorizeCookieTTL().Seconds()))
	}
	httpserver.Success(c, stdhttp.StatusOK, result.pair)
}

// loginErrorResponse maps known auth errors to HTTP status codes and messages.
func loginErrorResponse(err error) (int, string) {
	var lockoutErr *LockoutError
	if errors.As(err, &lockoutErr) {
		return stdhttp.StatusLocked, lockoutErr.Error()
	}
	if errors.Is(err, ErrAccountLocked) {
		return stdhttp.StatusLocked, err.Error()
	}
	if errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrUserDisabled) {
		return stdhttp.StatusUnauthorized, err.Error()
	}
	return stdhttp.StatusInternalServerError, "login unavailable"
}

// forgotPassword sends a password reset code to the user's email.
//
// Call chain: POST /password/forgot → forgotPassword → service.ForgotPassword → SendEmailCode(password_forgot)
//
// @Summary      Forgot password
// @Description  Sends a password reset verification code.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  object{email=string}  true  "User email"
// @Success      200   {object}  object
// @Failure      400   {object}  object
// @Router       /v1/auth/password/forgot [post]
func (h *Handler) forgotPassword(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	if !h.allowJSONRateLimit(c, passwordResetRateLimitScope, rateLimitKey(c, request.Email), passwordResetRateLimitLimit, passwordResetRateLimitWindow) {
		return
	}
	if err := h.service.ForgotPassword(c.Request.Context(), request.Email); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"sent": true})
}

// resetPassword resets the user's password using a verification code.
//
// Call chain: POST /password/reset → resetPassword → service.ResetPassword → requireEmailCode + repo.UpdatePassword
//
// @Summary      Reset password
// @Description  Resets password with a valid email verification code.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  object{email=string,email_code=string,password=string}  true  "Reset data"
// @Success      200   {object}  object
// @Failure      400   {object}  object
// @Router       /v1/auth/password/reset [post]
func (h *Handler) resetPassword(c *gin.Context) {
	var request struct {
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
		EmailCode   string `json:"email_code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	if !h.allowJSONRateLimit(c, passwordResetRateLimitScope, rateLimitKey(c, request.Email), passwordResetRateLimitLimit, passwordResetRateLimitWindow) {
		return
	}
	if err := h.service.ResetPassword(c.Request.Context(), ResetPasswordInput{
		Email:       request.Email,
		NewPassword: request.NewPassword,
		EmailCode:   request.EmailCode,
	}); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"reset": true})
}
