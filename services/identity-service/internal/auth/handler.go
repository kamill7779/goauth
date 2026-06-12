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

type Handler struct {
	service         *Service
	session         *session.Service
	rateLimiter     *ratelimit.Service
	captchaVerifier *captcha.Verifier
	captchaActions  map[string]struct{}

	registrationMode          string
	localPasswordLoginEnabled bool
}

var defaultCaptchaActions = []string{"login", "register", "email_code", "password_forgot"}

func NewHandler(service *Service, sessionService *session.Service) *Handler {
	return &Handler{
		service:                   service,
		session:                   sessionService,
		captchaActions:            captchaActionSet(defaultCaptchaActions),
		registrationMode:          "open",
		localPasswordLoginEnabled: true,
	}
}

func (h *Handler) SetRegistrationMode(mode string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "open"
	}
	h.registrationMode = mode
}

func (h *Handler) SetLocalPasswordLoginEnabled(enabled bool) {
	h.localPasswordLoginEnabled = enabled
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

func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.POST("/email/send-code", h.captchaMWFor("email_code"), h.sendCode)
	router.POST("/register", h.captchaMWFor("register"), h.register)
	router.POST("/login", h.captchaMWFor("login"), h.login)
	router.POST("/login/2fa/verify", h.loginTwoFactorVerify)
	router.POST("/password/forgot", h.captchaMWFor("password_forgot"), h.forgotPassword)
	router.POST("/password/reset", h.resetPassword)
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

	h.session.SetOIDCAuthorizeCookie(c, result.cookieValue, int(h.session.OIDCAuthorizeCookieTTL().Seconds()))
	httpserver.Success(c, stdhttp.StatusOK, result.pair)
}

func loginErrorResponse(err error) (int, string) {
	if errors.Is(err, ErrAccountLocked) {
		return stdhttp.StatusLocked, err.Error()
	}
	if errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrUserDisabled) {
		return stdhttp.StatusUnauthorized, err.Error()
	}
	return stdhttp.StatusInternalServerError, "login unavailable"
}

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
